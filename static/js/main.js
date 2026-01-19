// Flash message auto-hide
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.flash');
    
    flashMessages.forEach(function(flash) {
        setTimeout(function() {
            flash.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(function() {
                flash.remove();
            }, 300);
        }, 5000);
    });
});

// Animation for slide out
const style = document.createElement('style');
style.textContent = `
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Form validation
document.querySelectorAll('form').forEach(function(form) {
    form.addEventListener('submit', function(e) {
        const requiredFields = form.querySelectorAll('[required]');
        let isValid = true;
        
        requiredFields.forEach(function(field) {
            if (!field.value.trim()) {
                isValid = false;
                field.style.borderColor = '#e74c3c';
            } else {
                field.style.borderColor = '';
            }
        });
        
        if (!isValid) {
            e.preventDefault();
            alert('Please fill in all required fields');
        }
    });
});

// Confirm delete actions
document.querySelectorAll('form[action*="/delete/"]').forEach(function(form) {
    form.addEventListener('submit', function(e) {
        if (!confirm('Are you sure you want to delete this item?')) {
            e.preventDefault();
        }
    });
});
