param($username, $newPassword)

try {
    # Import the Active Directory module
    Import-Module ActiveDirectory

    # Convert the new password to a secure string
    $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force

    # Reset the user's password
    Set-ADAccountPassword -Identity $username -NewPassword $securePassword -Reset

    # Output success message
    Write-Output "Password reset successful for user: $username"
}
catch {
    # Output error message
    Write-Error $_.Exception.Message
    exit 1
}