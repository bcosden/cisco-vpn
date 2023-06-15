# https://learn.microsoft.com/en-us/azure/virtual-machines/windows/cli-ps-findimage
# https://learn.microsoft.com/en-us/powershell/module/az.compute/new-azvm?view=azps-9.4.0

###########################
# VARIABLES
###########################
$rg = "vwan-cisco-west"
$loc = "southcentralus"
$vmsize = "Standard_D2as_v5"
$VnetName = "ciscoWestNVA"
$remotePubIP = "20.225.39.126"
$remoteBGPIP = "10.0.1.15"
$remoteASN = "65507"
$localASN = "65503"
$addrSpace = "10.5.0.0/16"
$inside = "10.5.0.0/24"
$outside = "10.5.1.0/24"
$PreSharedKey = "abc123"
$tunnelBGPLocal = "192.168.3.1"
$tunnelBGPRemote = "192.168.4.1"

# regex for matching ip addresses up to 3rd octect
$matchStr = '[0-9]?[0-9]?[0-9].?[0-9]?[0-9]?[0-9].?[0-9]?[0-9]?[0-9].'

###########################
# FUNCTIONS
###########################

function Get-NetworkIPv4 {
    param(
        [string]$ipAddress,
        [int]$cidr
    )
    $parsedIpAddress = [System.Net.IPAddress]::Parse($ipAddress)
    $shift = 64 - $cidr
    
    [System.Net.IPAddress]$subnet = 0

    if ($cidr -ne 0) {
        $subnet = [System.Net.IPAddress]::HostToNetworkOrder([int64]::MaxValue -shl $shift)
    }

    [System.Net.IPAddress]$network = $parsedIpAddress.Address -band $subnet.Address

    return [PSCustomObject]@{
        Network = $network
        SubnetMask = $subnet
    }
}

###########################
# SCRIPT START
###########################

Write-Host "Get Proper Cisco Image"

# Find marketplace Image
$pubName = Get-AzVMImagePublisher -Location $loc | Where-Object PublisherName -Like "Cisco" | Select PublisherName
$offerName = Get-AzVMImageOffer -Location $loc -PublisherName $pubName.PublisherName | where Offer -eq 'cisco-csr-1000v'
$skuName = Get-AzVMImageSku -Location $loc -PublisherName $pubName.PublisherName -Offer $offerName.Offer | where Skus -eq '17_3_4a-byol'
$version = Get-AzVMImage -Location $loc -PublisherName $pubName.PublisherName -Offer $offerName.Offer -Sku $skuName.Skus | Select Version

Write-Host "Accept Terms for Marketplace Image"

# Accept terms for the Marketplace license. Does not hurt to do this each time.
Set-AzMarketplaceTerms -Publisher $pubName.PublisherName -Product $offerName.Offer -Name $skuName.Skus -Accept

# $urn = "$($pubName.PublisherName):$($offerName.Offer):$($skuName.Skus):$($version.Version)"
# $vmImage = Get-AzVMImage -Location $loc -PublisherName $pubName.PublisherName -Offer $offerName.Offer -Skus $skuName.Skus -Version $version.Version
# Get-AzMarketplaceterms -Publisher $pubName.PublisherName -Product $offerName.Offer -Name $skuName.Skus

Write-Host "Create Resource Group" $rg

New-AzResourceGroup -Name $rg -Location $loc

Write-Host "Create Network Security Group"

$myipobj = Invoke-WebRequest -Uri "ifconfig.io"
$myip = $myipobj.Content -replace "`n","/32"

$rule1 = New-AzNetworkSecurityRuleConfig -Name "Allow-SSH" `
	-Description "Allow SSH" `
    -Access Allow -Protocol Tcp `
	-Direction Inbound `
	-Priority 100 `
	-SourceAddressPrefix $myip `
	-SourcePortRange * `
	-DestinationAddressPrefix * `
	-DestinationPortRange 22

$nsg = New-AzNetworkSecurityGroup -Name "cisco-nsg" -ResourceGroupName $rg -Location $loc -SecurityRules $rule1

# Add NSG to existing Vnet -- not needed here for now
#
# $subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name outside 
# Set-AzVirtualNetworkSubnetConfig -Name $subnet.Name -VirtualNetwork $VNet -AddressPrefix $subnet.AddressPrefix -NetworkSecurityGroup $nsg
# $VNet | Set-AzVirtualNetwork

Write-Host "Create Subnets"

$insideSubnet = @{
	Name = 'inside'
	AddressPrefix = $inside
}

$outsideSubnet = @{
	Name = 'outside'
	AddressPrefix = $outside
	NetworkSecurityGroup = $nsg
}

Write-Host "Create Virtual Network"

$vnet = New-AzVirtualNetwork -Name $vnetName `
	-ResourceGroupName $rg `
	-Location $loc `
	-AddressPrefix $addrSpace `
	-Subnet $insideSubnet, $outsideSubnet

$pip = New-AzPublicIpAddress -Name 'ciscoNVA-pip' -ResourceGroupName $rg -Location $loc -Sku Standard -AllocationMethod Static -WarningAction Ignore

Write-Host "Create Network Interfaces"

$outmatch = ($outside | Select-String -Pattern $matchStr)
$outsideIP = "$($outmatch.Matches.Value)4"

$inmatch = ($inside | Select-String -Pattern $matchStr)
$insideIP = "$($inmatch.Matches.Value)4"

$nic1 = New-AzNetworkInterface -Name "outside" `
	-ResourceGroupName $rg `
	-Location $loc `
	-SubnetId $Vnet.Subnets[1].Id `
	-PublicIpAddressId $PIP.Id `
	-PrivateIpAddress $outsideIP

$nic2 = New-AzNetworkInterface -Name "inside" `
	-ResourceGroupName $rg `
	-Location $loc `
	-SubnetId $vnet.Subnets[0].Id `
	-PrivateIpAddress $insideIP

Write-Host "Enter Credentials:"

$cred = Get-Credential

Write-Host "Fixing bootstrap file for parameters set in script...."

$incidr = ($inside | Select-String -Pattern $matchStr)
$insideGW = "$($incidr.Matches.Value)1"

$ciscoInside = ($inside -split "/")
$netmask = Get-NetworkIPv4 $ciscoInside[0] $ciscoInside[1]

$file = ((Get-Content .\bootstrap) | ForEach-Object {
    $_.replace('OUTSIDE_IP', $outsideIP).
    replace('INSIDE_CIDR', $ciscoInside[0]). `
    replace('NETMASK', $netmask.SubnetMask.IPAddressToString). `
	replace('REMOTE_GW_IP', $remotePubIP). `
	replace('PRE_SHARED_KEY', $PreSharedKey). `
	replace('TUNNEL_BGP_LOCAL', $tunnelBGPLocal). `
	replace('TUNNEL_BGP_REMOTE', $tunnelBGPRemote). `
	replace('REMOTE_BGP_IP', $remoteBGPIP). `
	replace('LOCAL_ASN', $localASN). `
	replace('REMOTE_ASN', $remoteASN). `
	replace('INSIDE_GW', $insideGW) `
} | Out-String)

Write-Host "Configure VM"

$config = New-AzVMConfig -VMName "ciscoNVA" -VMSize $vmsize | Set-AzVMPlan -Publisher $pubName.PublisherName -Product $offerName.Offer -Name $skuName.Skus
$config = Set-AzVMOperatingSystem -VM $config -Linux -ComputerName "cisco" -Credential $cred -CustomData $file
$config = Add-AzVMNetworkInterface -VM $config -Id $nic1.Id -Primary
$config = Add-AzVMNetworkInterface -VM $config -Id $nic2.Id
$config = Set-AzVMSourceImage -VM $config -PublisherName $pubName.PublisherName -Offer $offerName.Offer -Skus $skuName.Skus -Version $version.Version

Write-Host "Create VM"

New-AzVM -ResourceGroupName $rg -Location $loc -VM $config -WarningAction Ignore

###########################
# SCRIPT END
###########################
