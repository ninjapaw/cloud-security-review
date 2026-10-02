param(
  [string]$SubscriptionId = '16037566-d4df-4c7c-b484-346d8472b4c4',
  [string]$ResourceGroup = 'NP-CloudSecurityReview-Dev-CentralUS',
  [string]$SiteName = 'np-cloudsecurityreview-demo-centralus',
  [string]$Location = 'centralus'
)

$ErrorActionPreference = 'Stop'
$current = az account show --query id -o tsv
if ($LASTEXITCODE -ne 0 -or $current -ne $SubscriptionId) {
  throw "Select the approved subscription $SubscriptionId before provisioning."
}

$exists = az group exists --name $ResourceGroup --subscription $SubscriptionId -o tsv
if ($LASTEXITCODE -ne 0) { throw 'Unable to check the target resource group.' }
if ($exists -eq 'false') {
  az group create --name $ResourceGroup --location $Location --subscription $SubscriptionId --output none
  if ($LASTEXITCODE -ne 0) { throw 'Resource group creation failed.' }
} elseif ($exists -eq 'true') {
  $actualLocation = az group show --name $ResourceGroup --subscription $SubscriptionId --query location -o tsv
  if ($LASTEXITCODE -ne 0 -or $actualLocation -ne $Location) {
    throw "The existing resource group is not in $Location."
  }
} else {
  throw 'Unable to determine whether the resource group exists.'
}

$site = az staticwebapp list --resource-group $ResourceGroup --subscription $SubscriptionId `
  --query "[?name=='$SiteName'].{name:name,sku:sku.name,location:location,repositoryUrl:repositoryUrl,defaultHostname:defaultHostname}" -o json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Unable to check the target Static Web App.' }
if ($site) {
  if ($site.sku -ne 'Free' -or $site.location -ne 'Central US' -or $site.repositoryUrl) {
    throw 'The existing site does not match the approved free, unconnected deployment.'
  }
  Write-Output "Existing approved site: https://$($site.defaultHostname)"
} else {
  az staticwebapp create --name $SiteName --resource-group $ResourceGroup `
    --location $Location --sku Free --subscription $SubscriptionId `
    --query '{name:name,location:location,sku:sku.name,defaultHostname:defaultHostname}' -o json
  if ($LASTEXITCODE -ne 0) { throw 'Static Web App provisioning failed.' }
}
