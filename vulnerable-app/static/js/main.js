/* =============================================================================
   VulnShop - Main JavaScript
   ============================================================================= */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize cart count
    updateCartCount();

    // Add to cart buttons
    initAddToCartButtons();

    // CSRF token for AJAX requests
    initCSRFToken();
});

/**
 * Update cart count badge
 */
function updateCartCount() {
    const cartCookie = getCookie('cart');
    if (cartCookie) {
        try {
            // Note: This is a simple count, the actual cart uses pickle
            // which we can't decode in JS. In a real app, we'd have an API endpoint.
            const badge = document.getElementById('cart-count');
            if (badge) {
                badge.textContent = '?'; // We can't actually decode pickle in JS
            }
        } catch (e) {
            console.error('Error parsing cart:', e);
        }
    }
}

/**
 * Initialize add to cart buttons
 */
function initAddToCartButtons() {
    const buttons = document.querySelectorAll('.add-to-cart');

    buttons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();

            const productId = this.getAttribute('data-product-id');
            const quantity = 1;

            addToCart(productId, quantity, this);
        });
    });
}

/**
 * Add product to cart
 */
function addToCart(productId, quantity, button) {
    const originalText = button.textContent;
    button.textContent = 'Adding...';
    button.disabled = true;

    const formData = new FormData();
    formData.append('quantity', quantity);

    fetch('/cart/add/' + productId + '/', {
        method: 'POST',
        body: formData,
        headers: {
            'X-CSRFToken': getCSRFToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            button.textContent = 'Added!';
            button.classList.remove('btn-primary');
            button.classList.add('btn-success');

            // Update cart count
            const badge = document.getElementById('cart-count');
            if (badge && data.cart_count) {
                badge.textContent = data.cart_count;
            }

            setTimeout(function() {
                button.textContent = originalText;
                button.classList.remove('btn-success');
                button.classList.add('btn-primary');
                button.disabled = false;
            }, 2000);
        } else {
            button.textContent = 'Error';
            setTimeout(function() {
                button.textContent = originalText;
                button.disabled = false;
            }, 2000);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        button.textContent = 'Error';
        setTimeout(function() {
            button.textContent = originalText;
            button.disabled = false;
        }, 2000);
    });
}

/**
 * Initialize CSRF token for AJAX
 */
function initCSRFToken() {
    // Get CSRF token from cookie
    const csrfToken = getCSRFToken();

    // Add to default fetch headers
    if (csrfToken) {
        const originalFetch = window.fetch;
        window.fetch = function(url, options = {}) {
            options.headers = options.headers || {};
            if (!(options.headers instanceof Headers)) {
                if (!options.headers['X-CSRFToken']) {
                    options.headers['X-CSRFToken'] = csrfToken;
                }
            }
            return originalFetch(url, options);
        };
    }
}

/**
 * Get CSRF token from cookies
 */
function getCSRFToken() {
    return getCookie('csrftoken');
}

/**
 * Get cookie by name
 */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

/**
 * Format currency
 */
function formatCurrency(amount) {
    return '$' + parseFloat(amount).toFixed(2);
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    const container = document.querySelector('.container');
    if (!container) return;

    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.role = 'alert';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

    container.insertBefore(alert, container.firstChild);

    // Auto dismiss after 5 seconds
    setTimeout(function() {
        alert.classList.remove('show');
        setTimeout(function() {
            alert.remove();
        }, 150);
    }, 5000);
}

/**
 * Confirm action
 */
function confirmAction(message) {
    return confirm(message);
}

/**
 * Format date
 */
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}
