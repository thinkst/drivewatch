Drivewatch
===================================

Thinkst Applied Research

Overview
------------
Drivewatch allows you to monitor your companies Google Drive for suspicious activity. It makes use of the Google Reports API: https://developers.google.com/admin-sdk/reports/v1/get-start/getting-started.

.. _installation:

Installation
------------

The API is supported on python 2.7. Install the dependencies using:

.. code-block:: bash

   pip install -r REQUIREMENTS.txt

For instructions on installing python and pip see "The Hitchhiker's Guide to
Python" `Installation Guides
<http://docs.python-guide.org/en/latest/starting/installation/>`_.

**Note:** This has currently only been tested on MacOS and Linux systems. There may be some small hiccups on Windows boxes.

Required Steps
----------

In order to use Drivewatch you will need a few things including: an account with Administrator privileges  for the GSuite Domain and a project in the Google cloud console. 

Follow these steps to get the Google side of things setup:

A new project will need to be created at https://console.cloud.google.com and the relevant
APIs enabled. In this case the enabled applications are the "Admin SDK" and the "Apps Activity API". 

Once the project has been created a new OAuth 2.0 Client ID will need to be created. this
may be done under the Credentials tab of the newly created project. Once this has been done you'll need to keep the Client ID handy. **Note:** You'll also want to download the client_secret.json file here
and make sure it's called "client_secret.json".

Now log into the admin homepage (Google Admin - Google Accounts) and navigate to Security Settings and when here head to Advanced. Under advanced you will see a 
Authentication section, click Manage API client access. This will bring up a new page. This is were that OAuth Client ID will come in handy. Create a new access rule using the Client ID in the Client Name field and the following for the Scopes field: 	https://www.googleapis.com/auth/admin.reports.audit.readonly.
This will give the OAuth user access to the Reports API.

All that's needed now is to run the tool and login via OAuth. **Note:** Make sure you are logged into the Admin account in your browser as this is required for OAuth auth step to work correctly.

Alert Types
----------

**Document Tokens:** A specific document is monitored for acitivity. If the document is viewed for example, an alert is generated.

**User Tokens:** A particular user is watched to monitor any activity that takes place in his/her drive. **Note:** User tokens will not be triggered by the User being tokened.

**Threshold:** Passive monitoring. Applies to all users in the organization. If a user views more than 30 unique documents within 24 hours, an alert is fired.

**Baseline:** Passive monitoring. Applies to all users in the organization. When the tool is first launched the history of each user (activity up to 180 days old) is parsed to build a baseline for each user.
This is used to determine the average daily activity for each user. If a user goes above 120% of their average daily drive activity, an alert is fired.


Syslog Integration
----------
Syslog is enabled by default. The messages are sent with the "drivewatch" program-name and are of the log level CRITICAL. These are logged to the local machine. Remote logging will need to be configured in the syslog daemon's config.

Configuration
----------

Configuring the tool is done via the file "config.json". Document tokens and User tokens can be specified here. Logging can also be enabled but is not recommended as it logs all Drive activity. Look at the "cfgs" directory for examples.

Running the tool
----------

Now for the fun part! To run the tool simply run:

.. code-block:: bash

   python driveWatch.python

If this is your first time running the tool you will be directed to a new tab on your web browser with steps to complete OAuth authentication. This will only need to be done once.

Now just sit back and relax while the alerts come through!

Discussion and Support
---------------------------

Please file bugs and feature requests as issues on `GitHub
<https://github.com/thinkst/drivewatch/issues>`_ after first searching to ensure a
similar issue was not already filed. If such an issue already exists please
give it a thumbs up reaction. Comments to issues containing additional
information are certainly welcome.

License
-------

The Drivewatch tool source (v1.0.0+) is provided under the `Revised BSD License
<https://github.com/thinkst/drivewatch/blob/master/LICENSE.txt>`_.

* Copyright (c), 2017, Thinkst Applied Research
