// Encryption toggle handler
document.getElementById('defaultEncryption')?.addEventListener('change', async function(e) {
    const messageDiv = document.getElementById('encryptionMessage');
    try {
        const response = await fetch('/api/settings/encryption', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                enabled: e.target.checked
            })
        });
        if (!response.ok) throw new Error('Failed to update encryption settings');
        
        messageDiv.textContent = 'Encryption settings updated successfully';
        messageDiv.className = 'alert alert-success mt-2';
        messageDiv.style.display = 'block';
        setTimeout(() => {
            messageDiv.style.display = 'none';
        }, 3000);
    } catch (error) {
        console.error('Error:', error);
        messageDiv.textContent = 'Failed to update encryption settings';
        messageDiv.className = 'alert alert-danger mt-2';
        messageDiv.style.display = 'block';
        // Reset the toggle if the update failed
        e.target.checked = !e.target.checked;
    }
});

// 2FA toggle handler
document.getElementById('enable2FA')?.addEventListener('change', async function(e) {
    const settingsDiv = document.getElementById('2faSettings');
    const messageDiv = document.getElementById('2faMessage');
    try {
        const response = await fetch('/api/settings/2fa', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                enabled: e.target.checked
            })
        });
        
        if (!response.ok) throw new Error('Failed to update 2FA settings');
        
        messageDiv.textContent = '2FA settings updated successfully';
        messageDiv.className = 'alert alert-success mt-2';
        messageDiv.style.display = 'block';
        
        if (e.target.checked) {
            settingsDiv.style.display = 'block';
        } else {
            settingsDiv.style.display = 'none';
        }
        
        setTimeout(() => {
            messageDiv.style.display = 'none';
        }, 3000);
    } catch (error) {
        console.error('Error:', error);
        messageDiv.textContent = 'Failed to update 2FA settings';
        messageDiv.className = 'alert alert-danger mt-2';
        messageDiv.style.display = 'block';
        // Reset the toggle if the update failed
        e.target.checked = !e.target.checked;
        if (!e.target.checked) {
            settingsDiv.style.display = 'none';
        }
    }
});

// Phone number save handler

document.getElementById('savePhoneNumber')?.addEventListener('click', async function() {
    const phoneInput = document.getElementById('phoneNumber');
    const messageDiv = document.getElementById('phoneMessage');
    
    console.log('Saving phone number:', phoneInput.value);
    
    try {
        const response = await fetch('/api/settings/phone', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                phone_number: phoneInput.value
            })
        });
        
        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);
        
        if (!response.ok) {
            throw new Error(data.message || 'Failed to update phone number');
        }
        
        messageDiv.textContent = data.message || 'Phone number updated successfully';
        messageDiv.className = 'alert alert-success mt-2';
        messageDiv.style.display = 'block';
        
        setTimeout(() => {
            messageDiv.style.display = 'none';
        }, 3000);
    } catch (error) {
        console.error('Error:', error);
        messageDiv.textContent = error.message || 'Failed to update phone number';
        messageDiv.className = 'alert alert-danger mt-2';
        messageDiv.style.display = 'block';
    }
});

// File upload encryption progress
function updateEncryptionProgress(progress) {
    const progressBar = document.querySelector('#encryptionProgressModal .progress-bar');
    if (progressBar) {
        progressBar.style.width = `${progress}%`;
        if (progress >= 100) {
            setTimeout(() => {
                $('#encryptionProgressModal').modal('hide');
            }, 500);
        }
    }
}