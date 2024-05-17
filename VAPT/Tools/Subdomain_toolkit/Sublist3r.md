https://github.com/aboul3la/Sublist3r

Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS.

┌──(kali㉿kali)-[~]
└─$ `sublist3r -h `                               
usage: sublist3r [-h] -d DOMAIN [-b [BRUTEFORCE]] [-p PORTS] [-v [VERBOSE]] [-t THREADS] [-e ENGINES] [-o OUTPUT]
                 [-n]

OPTIONS:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to enumerate it's subdomains
  -b [BRUTEFORCE], --bruteforce [BRUTEFORCE]
                        Enable the subbrute bruteforce module
  -p PORTS, --ports PORTS
                        Scan the found subdomains against specified tcp ports
  -v [VERBOSE], --verbose [VERBOSE]
                        Enable Verbosity and display results in realtime
  -t THREADS, --threads THREADS
                        Number of threads to use for subbrute bruteforce
  -e ENGINES, --engines ENGINES
                        Specify a comma-separated list of search engines
  -o OUTPUT, --output OUTPUT
                        Save the results to text file
  -n, --no-color        Output without color

Example: python3 /usr/bin/sublist3r -d google.com


┌──(kali㉿kali)-[~]
└─$ `sublist3r -d tesla.com`

                 ____        _     _ _     _   _____                                                                
                / ___| _   _| |__ | (_)___| |_|___ / _ __                                                           
                \___ \| | | | '_ \| | / __| __| |_ \| '__|                                                          
                 ___) | |_| | |_) | | \__ \ |_ ___) | |                                                             
                |____/ \__,_|_.__/|_|_|___/\__|____/|_|                                                             
                                                                                                                    
                # Coded By Ahmed Aboul-Ela - @aboul3la                                                              
                                                                                                                    
[-] Enumerating subdomains now for tesla.com                                                                        
[-] Searching now in Baidu..
[-] Searching now in Yahoo..
[-] Searching now in Google..
[-] Searching now in Bing..
[-] Searching now in Ask..
[-] Searching now in Netcraft..
[-] Searching now in DNSdumpster..
[-] Searching now in Virustotal..
[-] Searching now in ThreatCrowd..
[-] Searching now in SSL Certificates..
[-] Searching now in PassiveDNS..
[!] Error: Virustotal probably now is blocking our requests
[-] Total Unique Subdomains Found: 312
www.tesla.com
CitiBankStatementSHA512.tesla.com
OpenADRClient.tesla.com
ai-api.tesla.com
ai-api-stg.tesla.com
ai-api-uat.tesla.com
akamai-apigateway-vehicleextinfogw-prdsvc-st.tesla.com
akamai-apigateway-vehicleextinfogw-stgsvc-st.tesla.com
ams13-gpgw1.tesla.com
apac-cppm.tesla.com
apacvpn.tesla.com
apacvpn1.tesla.com
apacvpn2.tesla.com
api-account-master.tesla.com
api-toolbox.tesla.com
sentry.app.tesla.com
appplayer.tesla.com
autodiscover.tesla.com
awsbtest.tesla.com
bctpay.tesla.com
billing.tesla.com
bom01-gpgw1.tesla.com
ca.tesla.com
ciscoguest.tesla.com
citiapiencpoc.tesla.com
citiapiencpocV2.tesla.com
citiapiencpocV3.tesla.com
citiapisslpoc.tesla.com
citiapisslpocV2.tesla.com
citiapisslpocV3.tesla.com
fleetview.prd.america.vn.cloud.tesla.com
apf-api.eng.vn.cloud.tesla.com
mobile-links.eng.vn.cloud.tesla.com
mobile-links-cdn.eng.vn.cloud.tesla.com
owner-api.eng.vn.cloud.tesla.com
signaling-robotics.eng.vn.cloud.tesla.com
vehicle-files.eng.vn.cloud.tesla.com
fleet-api.prd.eu.vn.cloud.tesla.com
fleetview.prd.europe.vn.cloud.tesla.com
vehicle-files.eng.euw1.vn.cloud.tesla.com
vehicle-files.prd.euw1.vn.cloud.tesla.com
fleet-api.prd.na.vn.cloud.tesla.com
apf-api.prd.vn.cloud.tesla.com
mobile-links.prd.vn.cloud.tesla.com
mobile-links-cdn.prd.vn.cloud.tesla.com
mobile-ops-links.prd.vn.cloud.tesla.com
vehicle-files.prd.vn.cloud.tesla.com
acme-sentry-4.eng.use1.vn.cloud.tesla.com
acme-sentry-4a.eng.use1.vn.cloud.tesla.com
vehicle-files.eng.usw2.vn.cloud.tesla.com
vehicle-files.prd.usw2.vn.cloud.tesla.com
cn.tesla.com
cnvpn.tesla.com
cnvpn1.tesla.com
manager.courses.tesla.com
sandbox-manager.courses.tesla.com
sandbox-studio.courses.tesla.com
www.sandbox-studio.courses.tesla.com
studio.courses.tesla.com
cradlepointtest01.tesla.com
cryptopay.tesla.com
cryptopay2.tesla.com
cryptopay3.tesla.com
cryptopay4.tesla.com
cx-apac.tesla.com
cx-apac-stg.tesla.com
cx-api-apac.tesla.com
cx-api-apac-stg.tesla.com
cxadmin-apac.tesla.com
cxadmin-apac-stg.tesla.com
cxadmin-api-apac.tesla.com
cxadmin-api-apac-stg.tesla.com
cxengine-apac.tesla.com
cxengine-apac-stg.tesla.com
cyberbeer.tesla.com
dal11-gpgw1.tesla.com
de.tesla.com
dev.tesla.com
dev-hermes-qd.tesla.com
dgf.tesla.com
digitalassets.tesla.com
digitalassets-accounts.tesla.com
digitalassets-contents.tesla.com
digitalassets-energy.tesla.com
digitalassets-learning.tesla.com
digitalassets-secure.tesla.com
digitalassets-shop.tesla.com
digitalassets-stage.tesla.com
click.emails.tesla.com
image.emails.tesla.com
view.emails.tesla.com
employee-teslatequila.tesla.com
employeefeedback.tesla.com
energy.tesla.com
gridlogic.energy.tesla.com
www.gridlogic.energy.tesla.com
gridlogic-eng.energy.tesla.com
powerhub.energy.tesla.com
www.powerhub.energy.tesla.com
autobidder.powerhub.energy.tesla.com
autobidder-eng.powerhub.energy.tesla.com
autobidder-preprd.powerhub.energy.tesla.com
gridlogic.powerhub.energy.tesla.com
gridlogic-eng.powerhub.energy.tesla.com
energydesk.tesla.com
energysupport.tesla.com
engage.tesla.com
eua-origin.tesla.com
eumirror.tesla.com
events.tesla.com
factory-berlin.tesla.com
feedback.tesla.com
fleetview.america.fn.tesla.com
fleetview.prd.america.fn.tesla.com
fleetview.prd.eu.fn.tesla.com
fleetview.europe.fn.tesla.com
fleetview.prd.europe.fn.tesla.com
fleetview.prd.euw1.fn.tesla.com
fleetview.fn.tesla.com
fleetview.prd.na.fn.tesla.com
fleetview.prd.usw2.fn.tesla.com
forums.tesla.com
fra05-gpgw1.tesla.com
gf.tesla.com
gigabier.tesla.com
github.tesla.com
assets.github.tesla.com
avatars.github.tesla.com
codeload.github.tesla.com
docker.github.tesla.com
gist.github.tesla.com
maven.github.tesla.com
media.github.tesla.com
notebooks.github.tesla.com
npm.github.tesla.com
nuget.github.tesla.com
pages.github.tesla.com
raw.github.tesla.com
render.github.tesla.com
reply.github.tesla.com
rubygems.github.tesla.com
s3-sidekick-ssl.github.tesla.com
uploads.github.tesla.com
viewscreen.github.tesla.com
github-ap.tesla.com
assets.github-ap.tesla.com
avatars.github-ap.tesla.com
codeload.github-ap.tesla.com
docker.github-ap.tesla.com
gist.github-ap.tesla.com
maven.github-ap.tesla.com
media.github-ap.tesla.com
notebook.github-ap.tesla.com
notebooks.github-ap.tesla.com
npm.github-ap.tesla.com
nuget.github-ap.tesla.com
pages.github-ap.tesla.com
raw.github-ap.tesla.com
render.github-ap.tesla.com
reply.github-ap.tesla.com
rubygems.github-ap.tesla.com
uploads.github-ap.tesla.com
viewscreen.github-ap.tesla.com
github-fw.tesla.com
assets.github-fw.tesla.com
avatars.github-fw.tesla.com
codeload.github-fw.tesla.com
docker.github-fw.tesla.com
gist.github-fw.tesla.com
maven.github-fw.tesla.com
media.github-fw.tesla.com
notebook.github-fw.tesla.com
notebooks.github-fw.tesla.com
npm.github-fw.tesla.com
nuget.github-fw.tesla.com
pages.github-fw.tesla.com
raw.github-fw.tesla.com
render.github-fw.tesla.com
reply.github-fw.tesla.com
rubygems.github-fw.tesla.com
uploads.github-fw.tesla.com
viewscreen.github-fw.tesla.com
github-it.tesla.com
assets.github-it.tesla.com
avatars.github-it.tesla.com
codeload.github-it.tesla.com
docker.github-it.tesla.com
gist.github-it.tesla.com
maven.github-it.tesla.com
media.github-it.tesla.com
notebook.github-it.tesla.com
notebooks.github-it.tesla.com
npm.github-it.tesla.com
nuget.github-it.tesla.com
pages.github-it.tesla.com
raw.github-it.tesla.com
render.github-it.tesla.com
reply.github-it.tesla.com
rubygems.github-it.tesla.com
uploads.github-it.tesla.com
viewscreen.github-it.tesla.com
githubmirror.tesla.com
githubmirroraus08.tesla.com
githubmirrorber02.tesla.com
gpv.tesla.com
hnd13-gpgw1.tesla.com
iad05-gpgw1.tesla.com
ion.tesla.com
ir.tesla.com
kronos.tesla.com
api.kronos.tesla.com
integration.kronos.tesla.com
mobile.kronos.tesla.com
wdm.kronos.tesla.com
wim.kronos.tesla.com
kronos-dev.tesla.com
kronosdb.tesla.com
dev.kronosdb.tesla.com
lax32-gpgw1.tesla.com
learning-apac.tesla.com
learning-apac-stg.tesla.com
lighthouse.tesla.com
lionpayshare.tesla.com
lionpaytest.tesla.com
lionshare.tesla.com
logcollector-ext.tesla.com
logtransit-ext.tesla.com
marketing.tesla.com
mfa-dev.tesla.com
mfamobile-dev.tesla.com
mfauser-dev.tesla.com
mfg.tesla.com
mirror.tesla.com
monitoring.tesla.com
monitoring-eu.tesla.com
my.tesla.com
naa-origin.tesla.com
nas-origin.tesla.com
new.tesla.com
new-dev.tesla.com
nv.tesla.com
ny.tesla.com
paloalto.tesla.com
paymentrecon.tesla.com
paymentrecon-stage.tesla.com
pilot-bpay.tesla.com
qa.tesla.com
raultest.tesla.com
referral.tesla.com
resources.tesla.com
rumipv6.tesla.com
studio.sandbox-courses.tesla.com
sc-cppm.tesla.com
sca.tesla.com
secureaccess.tesla.com
serviceapp.tesla.com
sin05-gpgw1.tesla.com
sjc36-gpgw1.tesla.com
sling.tesla.com
smarttax.tesla.com
smt.tesla.com
solarbonds.tesla.com
sso.tesla.com
sso-dec.tesla.com
sso-dev.tesla.com
sso-sandbox.tesla.com
sso-sig.tesla.com
stage.tesla.com
static.tesla.com
syd14-gpgw1.tesla.com
teslacmgap01.tesla.com
teslacmgcn01.tesla.com
teslacmgeu01.tesla.com
teslacmgna01.tesla.com
teslacmgus01.tesla.com
teslaquila.tesla.com
www.teslaquila.tesla.com
teslatequila.tesla.com
www.teslatequila.tesla.com
toolbox.tesla.com
www.toolbox.tesla.com
toolbox-beta.tesla.com
track.tesla.com
triton-management.tesla.com
triton-management-stg.tesla.com
triton-management-uat.tesla.com
triton-server.tesla.com
triton-server-stg.tesla.com
triton-server-uat.tesla.com
tvs.tesla.com
tvs-api.tesla.com
tvs-api-stg.tesla.com
tvs-api-uat.tesla.com
tvs-stg.tesla.com
tvs-uat.tesla.com
tx.tesla.com
ug.tesla.com
www.ug.tesla.com
vpn.tesla.com
vpn1.tesla.com
www.vpn1.tesla.com
vpn2.tesla.com
vpn3.tesla.com
vrp-stg.tesla.com
warpbilling.tesla.com
www-dev.tesla.com
www-stg2.tesla.com
www-test.tesla.com
www-uat.tesla.com
www-uat2.tesla.com
www45.tesla.com
xmail.tesla.com
