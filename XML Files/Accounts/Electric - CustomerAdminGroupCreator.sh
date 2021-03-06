#!/bin/bash
#
#
#
#           Created by A.Hodgson                     
#            Date: 2021-11-22                            
#            Purpose: Create a Jamf Pro user account via API with Electric's Read-Only Settings
#                   https://docs.google.com/document/d/1Vd7DsB1Wc_PKU_b-esxvEi6tDvMLEuxt8PdKG5huuhU/
#
#
#############################################################
#############################################################
# Just for fun
cat << "EOF"

        \|||/
        (o o)
-----ooO-(_)-Ooo-------

   Read-Only Account

EOF
#############################################################
# User Input
#############################################################
read -r -p "Please enter a JAMF instance to take action on: " jamfProURL
if [[ -z "$apiUser" ]]; then 
    read -r -p "Please enter a JAMF API administrator name: " apiUser
fi
if [[ -z "$apiPass" ]]; then 
    read -r -s -p "Please enter the password for the account: " apiPass
fi
echo ""

#############################################################
# Functions
#############################################################
function apiResponse() #takes api response code variable
{
    HTTP_Status=$1
    if [ $HTTP_Status -eq 200 ] || [ $HTTP_Status -eq 201 ]; then
        echo "Success."
    elif [ $HTTP_Status -eq 400 ]; then
        echo "Failure - Bad request. Verify the syntax of the request specifically the XML body."
    elif [ $HTTP_Status -eq 401 ]; then
        echo "Failure - Authentication failed. Verify the credentials being used for the request."
    elif [ $HTTP_Status -eq 403 ]; then
        echo "Failure - Invalid permissions. Verify the account being used has the proper permissions for the object/resource you are trying to access."
    elif [ $HTTP_Status -eq 404 ]; then
        echo "Failure - Object/resource not found. Verify the URL path is correct."
    elif [ $HTTP_Status -eq 409 ]; then
        echo "Failure - Conflict, check XML data"
    elif [ $HTTP_Status -eq 500 ]; then
        echo "Failure - Internal server error. Retry the request or contact Jamf support if the error is persistent."
    fi
}

function callAPI() #takes a jamfproURL variable
{
    echo "Acting on instance: $jamfProURL"
    api_response=$(curl --write-out "%{http_code}" -sku ${apiUser}:${apiPass} -H "Content-Type: text/xml" ${jamfProURL}/JSSResource/accounts/groupid/0 -d "$group_data" -X POST)
    responseStatus=${api_response: -3}
    apiResponse "$responseStatus"
}
#############################################################
group_data="
<group>
    <id>-1</id>
    <name>approved-admins</name>
    <access_level>Full Access</access_level>
    <privilege_set>Custom</privilege_set>
    <site>
        <id>-1</id>
        <name>None</name>
    </site>
    <privileges>
        <jss_objects>
        <privilege>Create Advanced Computer Searches</privilege>
        <privilege>Read Advanced Computer Searches</privilege>
        <privilege>Update Advanced Computer Searches</privilege>
        <privilege>Create Advanced Mobile Device Searches</privilege>
        <privilege>Read Advanced Mobile Device Searches</privilege>
        <privilege>Update Advanced Mobile Device Searches</privilege>
        <privilege>Create Advanced User Searches</privilege>
        <privilege>Read Advanced User Searches</privilege>
        <privilege>Update Advanced User Searches</privilege>
        <privilege>Create Advanced User Content Searches</privilege>
        <privilege>Read Advanced User Content Searches</privilege>
        <privilege>Update Advanced User Content Searches</privilege>
        <privilege>Create AirPlay Permissions</privilege>
        <privilege>Read AirPlay Permissions</privilege>
        <privilege>Update AirPlay Permissions</privilege>
        <privilege>Create Allowed File Extension</privilege>
        <privilege>Read Allowed File Extension</privilege>
        <privilege>Create_API_Integrations</privilege>
        <privilege>Read_API_Integrations</privilege>
        <privilege>Update_API_Integrations</privilege>
        <privilege>Create Attachment Assignments</privilege>
        <privilege>Read Attachment Assignments</privilege>
        <privilege>Update Attachment Assignments</privilege>
        <privilege>Read Device Enrollment Program Instances</privilege>
        <privilege>Create Buildings</privilege>
        <privilege>Read Buildings</privilege>
        <privilege>Update Buildings</privilege>
        <privilege>Create Categories</privilege>
        <privilege>Read Categories</privilege>
        <privilege>Update Categories</privilege>
        <privilege>Create Classes</privilege>
        <privilege>Read Classes</privilege>
        <privilege>Update Classes</privilege>
        <privilege>Create Computer Enrollment Invitations</privilege>
        <privilege>Read Computer Enrollment Invitations</privilege>
        <privilege>Update Computer Enrollment Invitations</privilege>
        <privilege>Create Computer Extension Attributes</privilege>
        <privilege>Read Computer Extension Attributes</privilege>
        <privilege>Update Computer Extension Attributes</privilege>
        <privilege>Create Custom Paths</privilege>
        <privilege>Read Custom Paths</privilege>
        <privilege>Update Custom Paths</privilege>
        <privilege>Read Computer PreStage Enrollments</privilege>
        <privilege>Create Computers</privilege>
        <privilege>Read Computers</privilege>
        <privilege>Update Computers</privilege>
        <privilege>Create Configurations</privilege>
        <privilege>Read Configurations</privilege>
        <privilege>Update Configurations</privilege>
        <privilege>Create Departments</privilege>
        <privilege>Read Departments</privilege>
        <privilege>Update Departments</privilege>
        <privilege>Create Device Name Patterns</privilege>
        <privilege>Read Device Name Patterns</privilege>
        <privilege>Update Device Name Patterns</privilege>
        <privilege>Create Directory Bindings</privilege>
        <privilege>Read Directory Bindings</privilege>
        <privilege>Update Directory Bindings</privilege>
        <privilege>Read Disk Encryption Configurations</privilege>
        <privilege>Read Disk Encryption Institutional Configurations</privilege>
        <privilege>Create Dock Items</privilege>
        <privilege>Read Dock Items</privilege>
        <privilege>Update Dock Items</privilege>
        <privilege>Create eBooks</privilege>
        <privilege>Read eBooks</privilege>
        <privilege>Update eBooks</privilege>
        <privilege>Create Enrollment Customizations</privilege>
        <privilege>Read Enrollment Customizations</privilege>
        <privilege>Update Enrollment Customizations</privilege>
        <privilege>Create Enrollment Profiles</privilege>
        <privilege>Read Enrollment Profiles</privilege>
        <privilege>Update Enrollment Profiles</privilege>
        <privilege>Create Patch External Source</privilege>
        <privilege>Read Patch External Source</privilege>
        <privilege>Update Patch External Source</privilege>
        <privilege>Create File Attachments</privilege>
        <privilege>Read File Attachments</privilege>
        <privilege>Update File Attachments</privilege>
        <privilege>Read Distribution Points</privilege>
        <privilege>Create Push Certificates</privilege>
        <privilege>Read Push Certificates</privilege>
        <privilege>Update Push Certificates</privilege>
        <privilege>Create iBeacon</privilege>
        <privilege>Read iBeacon</privilege>
        <privilege>Update iBeacon</privilege>
        <privilege>Create Infrastructure Managers</privilege>
        <privilege>Read Infrastructure Managers</privilege>
        <privilege>Update Infrastructure Managers</privilege>
        <privilege>Create Inventory Preload Records</privilege>
        <privilege>Read Inventory Preload Records</privilege>
        <privilege>Update Inventory Preload Records</privilege>
        <privilege>Create VPP Invitations</privilege>
        <privilege>Read VPP Invitations</privilege>
        <privilege>Update VPP Invitations</privilege>
        <privilege>Create Jamf Connect Deployments</privilege>
        <privilege>Read Jamf Connect Deployments</privilege>
        <privilege>Update Jamf Connect Deployments</privilege>
        <privilege>Create Jamf Protect Deployments</privilege>
        <privilege>Read Jamf Protect Deployments</privilege>
        <privilege>Update Jamf Protect Deployments</privilege>
        <privilege>Read Accounts</privilege>
        <privilege>Create JSON Web Token Configuration</privilege>
        <privilege>Read JSON Web Token Configuration</privilege>
        <privilege>Update JSON Web Token Configuration</privilege>
        <privilege>Create Licensed Software</privilege>
        <privilege>Read Licensed Software</privilege>
        <privilege>Update Licensed Software</privilege>
        <privilege>Create Mac Applications</privilege>
        <privilege>Read Mac Applications</privilege>
        <privilege>Update Mac Applications</privilege>
        <privilege>Create macOS Configuration Profiles</privilege>
        <privilege>Read macOS Configuration Profiles</privilege>
        <privilege>Update macOS Configuration Profiles</privilege>
        <privilege>Create Maintenance Pages</privilege>
        <privilege>Read Maintenance Pages</privilege>
        <privilege>Update Maintenance Pages</privilege>
        <privilege>Create Managed Preference Profiles</privilege>
        <privilege>Read Managed Preference Profiles</privilege>
        <privilege>Update Managed Preference Profiles</privilege>
        <privilege>Create Mobile Device Applications</privilege>
        <privilege>Read Mobile Device Applications</privilege>
        <privilege>Update Mobile Device Applications</privilege>
        <privilege>Create iOS Configuration Profiles</privilege>
        <privilege>Read iOS Configuration Profiles</privilege>
        <privilege>Update iOS Configuration Profiles</privilege>
        <privilege>Create Mobile Device Enrollment Invitations</privilege>
        <privilege>Read Mobile Device Enrollment Invitations</privilege>
        <privilege>Update Mobile Device Enrollment Invitations</privilege>
        <privilege>Create Mobile Device Extension Attributes</privilege>
        <privilege>Read Mobile Device Extension Attributes</privilege>
        <privilege>Update Mobile Device Extension Attributes</privilege>
        <privilege>Create Mobile Device Managed App Configurations</privilege>
        <privilege>Read Mobile Device Managed App Configurations</privilege>
        <privilege>Update Mobile Device Managed App Configurations</privilege>
        <privilege>Read Mobile Device PreStage Enrollments</privilege>
        <privilege>Create Mobile Devices</privilege>
        <privilege>Read Mobile Devices</privilege>
        <privilege>Update Mobile Devices</privilege>
        <privilege>Create Network Integration</privilege>
        <privilege>Read Network Integration</privilege>
        <privilege>Update Network Integration</privilege>
        <privilege>Create Network Segments</privilege>
        <privilege>Read Network Segments</privilege>
        <privilege>Update Network Segments</privilege>
        <privilege>Create Packages</privilege>
        <privilege>Read Packages</privilege>
        <privilege>Update Packages</privilege>
        <privilege>Create Patch Management Software Titles</privilege>
        <privilege>Read Patch Management Software Titles</privilege>
        <privilege>Update Patch Management Software Titles</privilege>
        <privilege>Create Patch Policies</privilege>
        <privilege>Read Patch Policies</privilege>
        <privilege>Update Patch Policies</privilege>
        <privilege>Create Peripheral Types</privilege>
        <privilege>Read Peripheral Types</privilege>
        <privilege>Update Peripheral Types</privilege>
        <privilege>Create Personal Device Configurations</privilege>
        <privilege>Read Personal Device Configurations</privilege>
        <privilege>Update Personal Device Configurations</privilege>
        <privilege>Create Personal Device Profiles</privilege>
        <privilege>Read Personal Device Profiles</privilege>
        <privilege>Update Personal Device Profiles</privilege>
        <privilege>Create Policies</privilege>
        <privilege>Read Policies</privilege>
        <privilege>Update Policies</privilege>
        <privilege>Create PreStages</privilege>
        <privilege>Read PreStages</privilege>
        <privilege>Update PreStages</privilege>
        <privilege>Create Printers</privilege>
        <privilege>Read Printers</privilege>
        <privilege>Update Printers</privilege>
        <privilege>Create Provisioning Profiles</privilege>
        <privilege>Read Provisioning Profiles</privilege>
        <privilege>Update Provisioning Profiles</privilege>
        <privilege>Create Push Certificates</privilege>
        <privilege>Read Push Certificates</privilege>
        <privilege>Update Push Certificates</privilege>
        <privilege>Create Removable MAC Address</privilege>
        <privilege>Read Removable MAC Address</privilege>
        <privilege>Update Removable MAC Address</privilege>
        <privilege>Create Restricted Software</privilege>
        <privilege>Read Restricted Software</privilege>
        <privilege>Update Restricted Software</privilege>
        <privilege>Create Scripts</privilege>
        <privilege>Read Scripts</privilege>
        <privilege>Update Scripts</privilege>
        <privilege>Create Self Service Bookmarks</privilege>
        <privilege>Read Self Service Bookmarks</privilege>
        <privilege>Update Self Service Bookmarks</privilege>
        <privilege>Read Self Service Branding Configuration</privilege>
        <privilege>Create Sites</privilege>
        <privilege>Read Sites</privilege>
        <privilege>Update Sites</privilege>
        <privilege>Create Smart Computer Groups</privilege>
        <privilege>Read Smart Computer Groups</privilege>
        <privilege>Update Smart Computer Groups</privilege>
        <privilege>Create Smart Mobile Device Groups</privilege>
        <privilege>Read Smart Mobile Device Groups</privilege>
        <privilege>Update Smart Mobile Device Groups</privilege>
        <privilege>Create Smart User Groups</privilege>
        <privilege>Read Smart User Groups</privilege>
        <privilege>Update Smart User Groups</privilege>
        <privilege>Create Software Update Servers</privilege>
        <privilege>Read Software Update Servers</privilege>
        <privilege>Update Software Update Servers</privilege>
        <privilege>Create Static Computer Groups</privilege>
        <privilege>Read Static Computer Groups</privilege>
        <privilege>Update Static Computer Groups</privilege>
        <privilege>Create Static Mobile Device Groups</privilege>
        <privilege>Read Static Mobile Device Groups</privilege>
        <privilege>Update Static Mobile Device Groups</privilege>
        <privilege>Create Static User Groups</privilege>
        <privilege>Read Static User Groups</privilege>
        <privilege>Update Static User Groups</privilege>
        <privilege>Create User Extension Attributes</privilege>
        <privilege>Read User Extension Attributes</privilege>
        <privilege>Update User Extension Attributes</privilege>
        <privilege>Create User</privilege>
        <privilege>Read User</privilege>
        <privilege>Update User</privilege>
        <privilege>Create VPP Assignment</privilege>
        <privilege>Read VPP Assignment</privilege>
        <privilege>Update VPP Assignment</privilege>
        <privilege>Read Volume Purchasing Administrator Accounts</privilege>
        <privilege>Create Webhooks</privilege>
        <privilege>Read Webhooks</privilege>
        <privilege>Update Webhooks</privilege>
      </jss_objects>
      <jss_settings>
        <privilege>Read Apple Configurator Enrollment</privilege>
        <privilege>Read Education Settings</privilege>
        <privilege>Read Mobile Device App Maintenance Settings</privilege>
        <privilege>Read Automatic Mac App Updates Settings</privilege>
        <privilege>Read Automatically Renew MDM Profile Settings</privilege>
        <privilege>Read Autorun Imaging</privilege>
        <privilege>Read Cache</privilege>
        <privilege>Read Change Management</privilege>
        <privilege>Read Computer Check-In</privilege>
        <privilege>Read Cloud Distribution Point</privilege>
        <privilege>Read Cloud Services Settings</privilege>
        <privilege>Read Clustering</privilege>
        <privilege>Read Computer Check-In</privilege>
        <privilege>Read Computer Inventory Collection</privilege>
        <privilege>Read Computer Inventory Collection Settings</privilege>
        <privilege>Read Conditional Access</privilege>
        <privilege>Read Device Compliance Information</privilege>
        <privilege>Read GSX Connection</privilege>
        <privilege>Read Patch Internal Source</privilege>
        <privilege>Read Jamf Connect Settings</privilege>
        <privilege>Read Jamf Imaging</privilege>
        <privilege>Read Parent App Settings</privilege>
        <privilege>Read Jamf Protect Settings</privilege>
        <privilege>Read JSS URL</privilege>
        <privilege>Read Teacher App Settings</privilege>
        <privilege>Read Limited Access Settings</privilege>
        <privilege>Read Retention Policy</privilege>
        <privilege>Read Mobile Device Inventory Collection</privilege>
        <privilege>Read Password Policy</privilege>
        <privilege>Read Patch Management Settings</privilege>
        <privilege>Read PKI</privilege>
        <privilege>Read Re-enrollment</privilege>
        <privilege>Read Computer Security</privilege>
        <privilege>Read Self Service</privilege>
        <privilege>Read App Request Settings</privilege>
        <privilege>Read Mobile Device Self Service</privilege>
        <privilege>Read SMTP Server</privilege>
        <privilege>Read SSO Settings</privilege>
        <privilege>Read User-Initiated Enrollment</privilege>
      </jss_settings>
      <jss_actions>
        <privilege>Allow User to Enroll</privilege>
        <privilege>Assign Users to Computers</privilege>
        <privilege>Assign Users to Mobile Devices</privilege>
        <privilege>Change Password</privilege>
        <privilege>Dismiss Notifications</privilege>
        <privilege>Enroll Computers and Mobile Devices</privilege>
        <privilege>Flush MDM Commands</privilege>
        <privilege>Flush Policy Logs</privilege>
        <privilege>Remove Jamf Parent management capabilities</privilege>
        <privilege>Remove restrictions set by Jamf Parent</privilege>
        <privilege>CLEAR_TEACHER_PROFILE_PRIVILEGE</privilege>
        <privilege>Jamf Connect Deployment Retry</privilege>
        <privilege>Jamf Protect Deployment Retry</privilege>
        <privilege>Send Application Attributes Command</privilege>
        <privilege>Send Blank Pushes to Mobile Devices</privilege>
        <privilege>Send Command to Renew MDM Profile</privilege>
        <privilege>Send Computer Bluetooth Command</privilege>
        <privilege>Send Computer Delete User Account Command</privilege>
        <privilege>Send Computer Remote Command to Download and Install OS X Update</privilege>
        <privilege>Send Computer Remote Command to Install Package</privilege>
        <privilege>Send Computer Remote Desktop Command</privilege>
        <privilege>Send Computer Remote Lock Command</privilege>
        <privilege>Send Computer Remote Wipe Command</privilege>
        <privilege>Send Computer Set Activation Lock Command</privilege>
        <privilege>Send Computer Unlock User Account Command</privilege>
        <privilege>Send Computer Unmanage Command</privilege>
        <privilege>Send Disable Bootstrap Token Command</privilege>
        <privilege>Send Email to End Users via JSS</privilege>
        <privilege>Send Enable Bootstrap Token Command</privilege>
        <privilege>Send Inventory Requests to Mobile Devices</privilege>
        <privilege>Send Messages to Self Service Mobile</privilege>
        <privilege>Send Mobile Device Bluetooth Command</privilege>
        <privilege>Send Mobile Device Diagnostics and Usage Reporting and App Analytics Commands</privilege>
        <privilege>Send Mobile Device Disable Data Roaming Command</privilege>
        <privilege>Send Mobile Device Disable Voice Roaming Command</privilege>
        <privilege>Send Mobile Device Enable Data Roaming Command</privilege>
        <privilege>Send Mobile Device Enable Voice Roaming Command</privilege>
        <privilege>Send Mobile Device Lost Mode Command</privilege>
        <privilege>Send Mobile Device Managed Settings Command</privilege>
        <privilege>Send Mobile Device Mirroring Command</privilege>
        <privilege>Send Mobile Device Personal Hotspot Command</privilege>
        <privilege>Send Mobile Device Software Update Recommendation Cadence Command</privilege>
        <privilege>Send Mobile Device Refresh Cellular Plans Command</privilege>
        <privilege>Send Mobile Device Remote Command to Download and Install iOS Update</privilege>
        <privilege>Send Mobile Device Remote Lock Command</privilege>
        <privilege>Send Mobile Device Remote Wipe Command</privilege>
        <privilege>Send Mobile Device Remove Passcode Command</privilege>
        <privilege>Send Mobile Device Remove Restrictions Password Command</privilege>
        <privilege>Send Mobile Device Restart Device Command</privilege>
        <privilege>Send Mobile Device Set Activation Lock Command</privilege>
        <privilege>Send Mobile Device Set Device Name Command</privilege>
        <privilege>Send Mobile Device Set Wallpaper Command</privilege>
        <privilege>Send Mobile Device Shared Device Configuration Commands</privilege>
        <privilege>Send Mobile Device Shared iPad Commands</privilege>
        <privilege>Send Mobile Device Shut Down Command</privilege>
        <privilege>Send Set Recovery Lock Command</privilege>
        <privilege>Send Set Timezone Command</privilege>
        <privilege>Send Software Update Settings Command</privilege>
        <privilege>Send Update Passcode Lock Grace Period Command</privilege>
        <privilege>Unmanage Mobile Devices</privilege>
        <privilege>View Activation Lock Bypass Code</privilege>
        <privilege>View Disk Encryption Recovery Key</privilege>
        <privilege>View Event Logs</privilege>
        <privilege>View Mobile Device Lost Mode Location</privilege>
        <privilege>View Recovery Lock</privilege>
      </jss_actions>
      <recon/>
      <casper_admin>
        <privilege>Use Casper Admin</privilege>
      </casper_admin>
      <casper_remote/>
      <casper_imaging/>
    </privileges>
    <members/>
</group>
"
#############################################################
# MAIN 
#############################################################
echo ""
callAPI "$jamfProURL"

exit 0
