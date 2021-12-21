#!/bin/bash
#
#
#
#           Created by A.Hodgson                     
#            Date: 2021-11-22                            
#            Purpose: Upload XML data to appropriate API endpoint 
#
#
#
#############################################################
apiUser=""
apiPass=""
#############################################################
# Configuration Arrays - format the array in terms of "api end point, github raw xml url"
#############################################################
malwarebytes_configprofile_new=(
		"osxconfigurationprofiles,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Malwarebytes/KernExtProfile-Malwarebytes.xml"
		"osxconfigurationprofiles,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Malwarebytes/PPPC-Malwarebytes.xml"
		"osxconfigurationprofiles,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Malwarebytes/SystExtProfile-MalwareBytes.xml"
)
#############################################################
OnePass_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/1passpolicy.xml")
eightxeight_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/8x8policy.xml")
acrobatreader_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/acrobatreaderpolicy.xml")
box_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/boxpolicy.xml")
dialpad_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/dialpadpolicy.xml")
Dropbox_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/dropboxpolicy.xml")
figma_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/figmapolicy.xml")
gdrive_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/drivepolicy.xml")
g2meeting_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/gotomeetingpolicy.xml")
office365_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/office365.xml")
msTeams_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/msteamspolicy.xml")
miro_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/miropolicy.xml")
notion_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/notionpolicy.xml")
sketch_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/sketchpolicy.xml")
zoom_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/zoompolicy.xml")
removeJamf_policy_new=("policies,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/Policies/removeFramework-Policy.xml")
#############################################################
advsearch_enrolledDEP=("advancedcomputersearches,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/AdvSearches/EnrolledviaDEP.xml")
advsearch_enrolledUIE=("advancedcomputersearches,https://raw.githubusercontent.com/Aaron-ElectricAI/JamfPro-XML/main/XML%20Files/AdvSearches/EnrolledviaUIE.xml")
#############################################################
# SCRIPT MENU HEADERS
#############################################################
function scriptheader()
{
cat << "EOF"


    .__________________________.
    | .___________________. |==|
    | |                   | |  |
    | |     ELECTRIC      | |  |
    | |        AI         | |  |
    | |                   | |  |
    | |     AUTOMATED     | |  |
    | |    PROVISIONING   | |  |
    | |                   | | ,|
    | !___________________! |(c|
    !_______________________!__!
   /                            \
  /  [][][][][][][][][][][][][]  \
 /  [][][][][][][][][][][][][][]  \
(  [][][][][____________][][][][]  )
 \ ------------------------------ /
  \______________________________/

EOF
}
function createPolicyHeader()
{
cat << "EOF"


 ___                                                                  _
/__/|__                         CREATE                             __//|
|__|/_/|__                    ENROLLMENT                         _/_|_||
|_|___|/_/|__                  POLICIES                       __/_|___||
|___|____|/_/|__                                           __/_|____|_||
|_|___|_____|/_/|_________________________________________/_|_____|___||
|___|___|__|___|/__/___/___/___/___/___/___/___/___/___/_|_____|____|_||
|_|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___||
|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|_||
|_|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|___|/

EOF
}
function modifyPolicyHeader()
{
cat << "EOF"


-. .-.   .-. .-.   .-. .-.   .  
||\|||\ /|||\|||\ /|||\|||\ /|
|/ \|||\|||/ \|||\|||/ \|||\||
~   `-~ `-`   `-~ `-`   `-~ `-
   MODIFY DEFAULT POLICIES   

EOF
}
function advSearchHeader()
{
cat << "EOF"


     __         __
   /.-'  ADV  `-.\
  //   SEARCHES  \\
 /j_______________j\
/o.-==-. .-. .-==-.o\
||      )) ((      ||
 \\____//   \\____// 
  `-==-'     `-==-'

EOF
}
#############################################################
# Functions
#############################################################
function apiResponse() #takes api response code variable
{
	status=${1: -3}
  if [ "$status" == "201" ] ; then
    echo "Success - $status"
  else
    echo "Failed - $status"
    echo "$1"
  fi
}

function callAPI() #takes an array element as paameter
{
	 configuration_array=("$@")

	# Loop to run all configurations
  for install_item in "${configuration_array[@]}"; do
    endpoint=$(echo "$install_item" | cut -d ',' -f1)
    url=$(echo "$install_item" | cut -d ',' -f2)
		xml=$(curl -sk -H "Authorization: token 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" -H 'Accept: application/vnd.github.v3.raw' $url)
		# get next enrollment policy ## and update the XML
		if [[ "$endpoint" == "policies" ]]
		then 
			policy_number=$(get_policy_number)
			xml=$( echo "$xml" | sed 's/XX/'${policy_number}'/g' )
		fi
		# Update Jamf	
		api_response=$(curl --write-out "%{http_code}" -sku ${apiUser}:${apiPass} -H "Content-Type: text/xml" ${jamfProURL}/JSSResource/${endpoint}/id/0 -d "${xml}" -X POST)
		apiResponse "$api_response"
	done			
}

function get_policy_number()
{
	#get policies
	enrollment_policys=$(curl -sku ${apiUser}:${apiPass} ${jamfProURL}/JSSResource/policies/category/Enrollment -H "accept: application/xml" -X GET)
	# trim out some bogus characters in a policy name '*'
	xml=$( echo "$enrollment_policys" | sed 's/\*/00/g' )

cat << EOF > /tmp/JSS_template.xslt
<?xml version="1.0" encoding="UTF-8"?>
	<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
		<xsl:output method="text"/>
		<xsl:template match="/">
			<xsl:for-each select="policies/policy">
				<xsl:value-of select="name"/>
				<xsl:text>|</xsl:text>
			</xsl:for-each>
		</xsl:template>
	</xsl:stylesheet>
EOF
	# Parse the XML
	enrollment_names=$( echo "$enrollment_policys" | xsltproc /tmp/JSS_template.xslt - )
	# Read enrollment category policy names to get the highest XX number value
	highcount=0
	while IFS='|' read -ra names; do
	  for name in "${names[@]}"; do
	    current_count=$(echo "${name}" | cut -c1-2)
	    if [[ $current_count =~ ^-?[0-9]+$ ]]
	 		then
	 			if [[ ${current_count#0} -gt ${highcount#0} ]]
	 			then
	 				highcount=$current_count
	 			fi
	 		fi 
	 	done
	done <<< "$enrollment_names"

	# Up the value to the next number so our new policy will fall in numberial order
	((highcount=highcount+1))
	nextNum=$(printf %02d $highcount)
	echo "$nextNum"
}

function createSearches()
{
	advSearchHeader
	#prompt user and loop until we have a valid option 
	while true; do
		echo ""
		echo "Select search to create:"
		echo "1 - Enrolled via DEP (macOS)"
		echo "2 - Enrolled via UIE (macOS)"
		echo ""
		echo "0 - Return to previous menu"
		echo "x - Exit"
		echo ""
		read -p "Please enter an option number: " option

		case $option in 
			1)
				callAPI "${advsearch_enrolledDEP[@]}"
				;;
			2) 
				callAPI "${advsearch_enrolledUIE[@]}"
				;;
			0)
				break
				;;
			x)
				exit 0
				;;
			*)
				echo "That is not a valid choice, try a number from the list."
	     	;;
	    esac
	done
}

function createPolicies()
{
	createPolicyHeader
	#prompt user and loop until we have a valid option 
	while true; do
		echo ""
		echo "Select software to deploy via Enrollment Configuration:"
		echo "1 - 1Password7"
		echo "2 - 8x8"
		echo "3 - Adobe Acrobat Reader DC"
		echo "4 - Box"
		echo "5 - Dialpad"
		echo "6 - Dropbox"
		echo "7 - Figma"
		echo "8 - Google Drive"
		echo "9 - Go-To Meeting"
		echo "10 - Microsoft Office 365"
		echo "11 - Microsoft Teams"
		echo "12 - Miro"
		echo "13 - Notion"
		echo "14 - Sketch"
		echo "15 - Zoom"
		echo "16 - jamf removeFramework"
		echo ""
		echo "0 - Return to previous menu"
		echo "x - Exit"
		echo ""
		read -p "Please enter an option number: " option

		case $option in
			1) # 1Password7
				callAPI "${OnePass_policy_new[@]}"
				;;
			2) # 8x8
				callAPI "${eightxeight_policy_new[@]}" 
				;;
			3) # Adobe Acrobat Reader DC
				callAPI "${acrobatreader_policy_new[@]}"
				;;
			4) # Box
				callAPI "${box_policy_new[@]}"
				;;
			5) # Dialpad
				callAPI "${dialpad_policy_new[@]}"
				;;
			6) # Dropbox
				callAPI "${Dropbox_policy_new[@]}"
				;;
			7) # Figma
				callAPI "${figma_policy_new[@]}"
				;; 
			8) # Google Drive
				callAPI "${gdrive_policy_new[@]}"
				;;
			9) # Go-To Meeting
				callAPI "${g2meeting_policy_new[@]}"
				;;
			10) # Office 365
				callAPI "${office365_policy_new[@]}"
				;;
			11) # Office Teams
				callAPI "${msTeams_policy_new[@]}"
				;;
			12) # Miro
				callAPI "${miro_policy_new[@]}"
				;;
			13) # Notion
				callAPI "${notion_policy_new[@]}"
				;;
			14) # Sketch
				callAPI "${sketch_policy_new[@]}"
				;;
			15) # Zoom
				callAPI "${zoom_policy_new[@]}"
				;;	
			16) # removeJamfFramework
				callAPI "${removeJamf_policy_new[@]}"
				;;
			0)
				break
				;;
			x)
				exit 0
				;;
			*)
				echo "That is not a valid choice, try a number from the list."
	     	;;
	    esac
	done
}

function modifyPolicies()
{
	modifyPolicyHeader
	#prompt user and loop until we have a valid option 
	while true; do
		echo ""
		echo "Select software policy to enable:"
		echo "1 - Zoom (Self Service)"
		echo "2 - Slack (Enrollment)"
		echo "3 - Google Chrome (Enrollment)"
		echo ""
		echo "0 - Return to previous menu"
		echo "x - Exit"
		echo ""
		read -p "Please enter an option number: " option

		case $option in 
			1) # Zoom
				api_response=$(curl --write-out "%{http_code}" -sku ${apiUser}:${apiPass} -H "Content-Type: text/xml" ${jamfProURL}/JSSResource/policies/id/74 -d "<policy><general><enabled>true</enabled></general></policy>" -X PUT)
				apiResponse "$api_response"
				;;
			2) # Slack
				api_response=$(curl --write-out "%{http_code}" -sku ${apiUser}:${apiPass} -H "Content-Type: text/xml" ${jamfProURL}/JSSResource/policies/id/65 -d "<policy><general><enabled>true</enabled></general></policy>" -X PUT)
				apiResponse "$api_response"
				;;
			3) # Google Drive
				api_response=$(curl --write-out "%{http_code}" -sku ${apiUser}:${apiPass} -H "Content-Type: text/xml" ${jamfProURL}/JSSResource/policies/id/66 -d "<policy><general><enabled>true</enabled></general></policy>" -X PUT)
				apiResponse "$api_response"
				;;
			0)
				break
				;;
			x)
				exit 0
				;;
			*)
				echo "That is not a valid choice, try a number from the list."
	     	;;
	    esac
	done
}

#############################################################
# MAIN
#############################################################
scriptheader

read -r -p "Please enter a JAMF instance to take action on: " jamfProURL
if [[ -z "$apiUser" ]]; then 
	read -r -p "Please enter a JAMF API administrator name: " apiUser
fi
if [[ -z "$apiPass" ]]; then 
	read -r -s -p "Please enter the password for the account: " apiPass
fi
echo ""
#prompt user and loop until we have a valid option 
while true; do
	echo ""
	echo "What would you like to do?"
	echo "1 - Create new policies"
	echo "2 - Modify existing policies"
	echo "3 - Create new advanced searches"
	echo "x - Exit"
	echo ""
	read -p "Please enter an option number: " option

	case $option in 
		1) 
			createPolicies
			;;
		2) 
			modifyPolicies
			;;
		3)
			createSearches
			;;
		x)
			exit 0
			;;
		*)
			echo "That is not a valid choice, try a number from the list."
     	;;
    esac
done
