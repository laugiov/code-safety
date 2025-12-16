/* =============================================================================
   Taint Analysis Masterclass - Custom JavaScript
   ============================================================================= */

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
  // Add copy functionality to code blocks (Material theme handles this, but we can extend)
  initCodeCopy();

  // Initialize any custom tooltips
  initTooltips();

  // Track outbound links (for analytics if enabled)
  trackOutboundLinks();
});

/**
 * Initialize additional code copy functionality
 */
function initCodeCopy() {
  // Material theme handles most of this, but we can add custom behavior
  const codeBlocks = document.querySelectorAll('pre code');

  codeBlocks.forEach(function(block) {
    // Add line numbers to specific code blocks if needed
    if (block.classList.contains('linenums')) {
      addLineNumbers(block);
    }
  });
}

/**
 * Add line numbers to code blocks
 */
function addLineNumbers(block) {
  const lines = block.textContent.split('\n');
  const numberedLines = lines.map(function(line, index) {
    return '<span class="line-number">' + (index + 1) + '</span>' + line;
  });
  block.innerHTML = numberedLines.join('\n');
}

/**
 * Initialize tooltips for vulnerability severity badges
 */
function initTooltips() {
  const tooltipElements = document.querySelectorAll('[data-tooltip]');

  tooltipElements.forEach(function(element) {
    element.addEventListener('mouseenter', function(e) {
      const tooltip = document.createElement('div');
      tooltip.className = 'custom-tooltip';
      tooltip.textContent = e.target.getAttribute('data-tooltip');
      document.body.appendChild(tooltip);

      const rect = e.target.getBoundingClientRect();
      tooltip.style.top = (rect.top - tooltip.offsetHeight - 5) + 'px';
      tooltip.style.left = (rect.left + rect.width / 2 - tooltip.offsetWidth / 2) + 'px';
    });

    element.addEventListener('mouseleave', function() {
      const tooltip = document.querySelector('.custom-tooltip');
      if (tooltip) {
        tooltip.remove();
      }
    });
  });
}

/**
 * Track outbound links for analytics
 */
function trackOutboundLinks() {
  const links = document.querySelectorAll('a[href^="http"]');

  links.forEach(function(link) {
    // Skip internal links
    if (link.hostname === window.location.hostname) {
      return;
    }

    link.addEventListener('click', function(e) {
      // If analytics is configured, track the click
      if (typeof gtag === 'function') {
        gtag('event', 'click', {
          'event_category': 'outbound',
          'event_label': link.href
        });
      }
    });
  });
}

/**
 * Smooth scroll to anchor links
 */
document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
  anchor.addEventListener('click', function(e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    }
  });
});
