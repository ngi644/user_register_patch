# encoding: utf-8

"""
Created by nagai at 15/03/23
"""

__author__ = 'nagai'

"""
Patch for Create account method

In lms.env.json add

`"WHITE_LIST_DOMAIN": ["safedomain.com", "safe2.example.com"]`

 to the list of FEATURES

"""

import re
import datetime
import logging
import time
from pytz import UTC

from django.conf import settings
from django.contrib.auth import logout, authenticate, login
from django.core.mail import send_mail
from django.core.validators import validate_email, validate_slug, ValidationError
from django.db import IntegrityError, transaction
from django_future.csrf import ensure_csrf_cookie
from django.utils.http import cookie_date, base36_to_int
from django.utils.translation import ugettext as _, get_language

from edxmako.shortcuts import render_to_response, render_to_string
from student.models import (
    Registration, UserProfile, PendingNameChange,
    PendingEmailChange, CourseEnrollment, unique_id_for_user,
    CourseEnrollmentAllowed, UserStanding, LoginFailures,
    create_comments_service_user, PasswordHistory, UserSignupSource,
    anonymous_id_for_user
)
import external_auth.views

from dogapi import dog_stats_api

from util.json_request import JsonResponse

from microsite_configuration import microsite

from util.password_policy_validators import (
    validate_password_length, validate_password_complexity,
    validate_password_dictionary
)

from third_party_auth import pipeline, provider

import analytics
from eventtracking import tracker
from student import views
from student.views import _do_create_account, AccountValidationError, AUDIT_LOG, try_change_enrollment


log = logging.getLogger("ou.student_patch")


@ensure_csrf_cookie
def create_account(request, post_override=None):  # pylint: disable-msg=too-many-statements
    """
    JSON call to create new edX account.
    Used by form in signup_modal.html, which is included into navigation.html
    """
    js = {'success': False}  # pylint: disable-msg=invalid-name

    post_vars = post_override if post_override else request.POST

    # allow for microsites to define their own set of required/optional/hidden fields
    extra_fields = microsite.get_value(
        'REGISTRATION_EXTRA_FIELDS',
        getattr(settings, 'REGISTRATION_EXTRA_FIELDS', {})
    )

    if settings.FEATURES.get('ENABLE_THIRD_PARTY_AUTH') and pipeline.running(request):
        post_vars = dict(post_vars.items())
        post_vars.update({'password': pipeline.make_random_password()})

    # if doing signup for an external authorization, then get email, password, name from the eamap
    # don't use the ones from the form, since the user could have hacked those
    # unless originally we didn't get a valid email or name from the external auth
    DoExternalAuth = 'ExternalAuthMap' in request.session
    if DoExternalAuth:
        eamap = request.session['ExternalAuthMap']
        try:
            validate_email(eamap.external_email)
            email = eamap.external_email
        except ValidationError:
            email = post_vars.get('email', '')
        if eamap.external_name.strip() == '':
            name = post_vars.get('name', '')
        else:
            name = eamap.external_name
        password = eamap.internal_password
        post_vars = dict(post_vars.items())
        post_vars.update(dict(email=email, name=name, password=password))
        log.debug(u'In create_account with external_auth: user = %s, email=%s', name, email)

    # Confirm we have a properly formed request
    for a in ['username', 'email', 'password', 'name']:
        if a not in post_vars:
            js['value'] = _("Error (401 {field}). E-mail us.").format(field=a)
            js['field'] = a
            return JsonResponse(js, status=400)

    if extra_fields.get('honor_code', 'required') == 'required' and \
            post_vars.get('honor_code', 'false') != u'true':
        js['value'] = _("To enroll, you must follow the honor code.").format(field=a)
        js['field'] = 'honor_code'
        return JsonResponse(js, status=400)

    # Can't have terms of service for certain SHIB users, like at Stanford
    tos_required = (
        not settings.FEATURES.get("AUTH_USE_SHIB") or
        not settings.FEATURES.get("SHIB_DISABLE_TOS") or
        not DoExternalAuth or
        not eamap.external_domain.startswith(
            external_auth.views.SHIBBOLETH_DOMAIN_PREFIX
        )
    )

    if tos_required:
        if post_vars.get('terms_of_service', 'false') != u'true':
            js['value'] = _("You must accept the terms of service.").format(field=a)
            js['field'] = 'terms_of_service'
            return JsonResponse(js, status=400)

    # Confirm appropriate fields are there.
    # TODO: Check e-mail format is correct.
    # TODO: Confirm e-mail is not from a generic domain (mailinator, etc.)? Not sure if
    # this is a good idea
    # TODO: Check password is sane

    required_post_vars = ['username', 'email', 'name', 'password']
    required_post_vars += [fieldname for fieldname, val in extra_fields.items()
                           if val == 'required']
    if tos_required:
        required_post_vars.append('terms_of_service')

    for field_name in required_post_vars:
        if field_name in ('gender', 'level_of_education'):
            min_length = 1
        else:
            min_length = 2

        if field_name not in post_vars or len(post_vars[field_name]) < min_length:
            error_str = {
                'username': _('Username must be minimum of two characters long'),
                'email': _('A properly formatted e-mail is required'),
                'name': _('Your legal name must be a minimum of two characters long'),
                'password': _('A valid password is required'),
                'terms_of_service': _('Accepting Terms of Service is required'),
                'honor_code': _('Agreeing to the Honor Code is required'),
                'level_of_education': _('A level of education is required'),
                'gender': _('Your gender is required'),
                'year_of_birth': _('Your year of birth is required'),
                'mailing_address': _('Your mailing address is required'),
                'goals': _('A description of your goals is required'),
                'city': _('A city is required'),
                'country': _('A country is required')
            }

            if field_name in error_str:
                js['value'] = error_str[field_name]
            else:
                js['value'] = _('You are missing one or more required fields')

            js['field'] = field_name
            return JsonResponse(js, status=400)

        max_length = 75
        if field_name == 'username':
            max_length = 30

        if field_name in ('email', 'username') and len(post_vars[field_name]) > max_length:
            error_str = {
                'username': _('Username cannot be more than {0} characters long').format(max_length),
                'email': _('Email cannot be more than {0} characters long').format(max_length)
            }
            js['value'] = error_str[field_name]
            js['field'] = field_name
            return JsonResponse(js, status=400)

    try:
        validate_email(post_vars['email'])
        email_domain = post_vars['email'].split('@')[-1]
        white_list_domain = settings.FEATURES.get('WHITE_LIST_DOMAIN', [])
        mth = [x for x in white_list_domain if re.search(x, email_domain)]
        if not mth:
            raise ValidationError(_(u'Enter a valid e-mail.'), code='invalid')
    except ValidationError:
        js['value'] = _("Valid e-mail is required.").format(field=a)
        js['field'] = 'email'
        return JsonResponse(js, status=400)

    try:
        validate_slug(post_vars['username'])
    except ValidationError:
        js['value'] = _("Username should only consist of A-Z and 0-9, with no spaces.").format(field=a)
        js['field'] = 'username'
        return JsonResponse(js, status=400)

    # enforce password complexity as an optional feature
    # but not if we're doing ext auth b/c those pws never get used and are auto-generated so might not pass validation
    if settings.FEATURES.get('ENFORCE_PASSWORD_POLICY', False) and not DoExternalAuth:
        try:
            password = post_vars['password']

            validate_password_length(password)
            validate_password_complexity(password)
            validate_password_dictionary(password)
        except ValidationError, err:
            js['value'] = _('Password: ') + '; '.join(err.messages)
            js['field'] = 'password'
            return JsonResponse(js, status=400)

    # allow microsites to define 'extended profile fields' which are
    # captured on user signup (for example via an overriden registration.html)
    # and then stored in the UserProfile
    extended_profile_fields = microsite.get_value('extended_profile_fields', [])
    extended_profile = None

    for field in extended_profile_fields:
        if field in post_vars:
            if not extended_profile:
                extended_profile = {}
            extended_profile[field] = post_vars[field]

    # Make sure that password and username fields do not match
    username = post_vars['username']
    password = post_vars['password']
    if username == password:
        js['value'] = _("Username and password fields cannot match")
        js['field'] = 'username'
        return JsonResponse(js, status=400)

    # Ok, looks like everything is legit.  Create the account.
    try:
        with transaction.commit_on_success():
            ret = _do_create_account(post_vars, extended_profile)
    except AccountValidationError as e:
        return JsonResponse({'success': False, 'value': e.message, 'field': e.field}, status=400)

    (user, profile, registration) = ret

    dog_stats_api.increment("common.student.account_created")

    email = post_vars['email']

    # Track the user's registration
    if settings.FEATURES.get('SEGMENT_IO_LMS') and hasattr(settings, 'SEGMENT_IO_LMS_KEY'):
        tracking_context = tracker.get_tracker().resolve_context()
        analytics.identify(user.id, {
            email: email,
            username: username,
        })

        registration_course_id = request.session.get('registration_course_id')
        analytics.track(
            user.id,
            "edx.bi.user.account.registered",
            {
                "category": "conversion",
                "label": registration_course_id
            },
            context={
                'Google Analytics': {
                    'clientId': tracking_context.get('client_id')
                }
            }
        )
        request.session['registration_course_id'] = None

    create_comments_service_user(user)

    context = {
        'name': post_vars['name'],
        'key': registration.activation_key,
    }

    # composes activation email
    subject = render_to_string('emails/activation_email_subject.txt', context)
    # Email subject *must not* contain newlines
    subject = ''.join(subject.splitlines())
    message = render_to_string('emails/activation_email.txt', context)

    # don't send email if we are doing load testing or random user generation for some reason
    if not (settings.FEATURES.get('AUTOMATIC_AUTH_FOR_TESTING')):
        from_address = microsite.get_value(
            'email_from_address',
            settings.DEFAULT_FROM_EMAIL
        )
        try:
            if settings.FEATURES.get('REROUTE_ACTIVATION_EMAIL'):
                dest_addr = settings.FEATURES['REROUTE_ACTIVATION_EMAIL']
                message = ("Activation for %s (%s): %s\n" % (user, user.email, profile.name) +
                           '-' * 80 + '\n\n' + message)
                send_mail(subject, message, from_address, [dest_addr], fail_silently=False)
            else:
                user.email_user(subject, message, from_address)
        except Exception:  # pylint: disable=broad-except
            log.error('Unable to send activation email to user from "{from_address}"'.format(from_address=from_address), exc_info=True)
            js['value'] = _('Could not send activation e-mail.')
            # What is the correct status code to use here? I think it's 500, because
            # the problem is on the server's end -- but also, the account was created.
            # Seems like the core part of the request was successful.
            return JsonResponse(js, status=500)

    # Immediately after a user creates an account, we log them in. They are only
    # logged in until they close the browser. They can't log in again until they click
    # the activation link from the email.
    login_user = authenticate(username=post_vars['username'], password=post_vars['password'])
    login(request, login_user)
    request.session.set_expiry(0)

    # TODO: there is no error checking here to see that the user actually logged in successfully,
    # and is not yet an active user.
    if login_user is not None:
        AUDIT_LOG.info(u"Login success on new account creation - {0}".format(login_user.username))

    if DoExternalAuth:
        eamap.user = login_user
        eamap.dtsignup = datetime.datetime.now(UTC)
        eamap.save()
        AUDIT_LOG.info("User registered with external_auth %s", post_vars['username'])
        AUDIT_LOG.info('Updated ExternalAuthMap for %s to be %s', post_vars['username'], eamap)

        if settings.FEATURES.get('BYPASS_ACTIVATION_EMAIL_FOR_EXTAUTH'):
            log.info('bypassing activation email')
            login_user.is_active = True
            login_user.save()
            AUDIT_LOG.info(u"Login activated on extauth account - {0} ({1})".format(login_user.username, login_user.email))

    dog_stats_api.increment("common.student.account_created")
    redirect_url = try_change_enrollment(request)

    # Resume the third-party-auth pipeline if necessary.
    if settings.FEATURES.get('ENABLE_THIRD_PARTY_AUTH') and pipeline.running(request):
        running_pipeline = pipeline.get(request)
        redirect_url = pipeline.get_complete_url(running_pipeline['backend'])

    response = JsonResponse({
        'success': True,
        'redirect_url': redirect_url,
    })

    # set the login cookie for the edx marketing site
    # we want this cookie to be accessed via javascript
    # so httponly is set to None

    if request.session.get_expire_at_browser_close():
        max_age = None
        expires = None
    else:
        max_age = request.session.get_expiry_age()
        expires_time = time.time() + max_age
        expires = cookie_date(expires_time)

    response.set_cookie(settings.EDXMKTG_COOKIE_NAME,
                        'true', max_age=max_age,
                        expires=expires, domain=settings.SESSION_COOKIE_DOMAIN,
                        path='/',
                        secure=None,
                        httponly=None)
    return response


views.create_account = create_account
