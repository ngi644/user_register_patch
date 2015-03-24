#Monky patch for create account method on Open edx

This patch is restrict user registration by domain.

##Install open edx environment

`sudo su - edxapp -s /bin/bash`

`. edxapp_env`

`pip install -e git+https://github.com/ngi644/user_register_patch`


##Add parameter

In `lms.env.json` and `cms.env.json`  file:

`"ADDL_INSTALLED_APPS": ["userregisterpatch"],`

 to the root node.


`"WHITE_LIST_DOMAIN": ["safedomain.com", "safe2.example.com"]`

 to the list of `FEATURES`.


##Restart edxapp

`sudo /edx/bin/supervisorctl restart edxapp:`
