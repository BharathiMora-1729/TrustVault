/**
 * Global TrustVault Frontend JavaScript Utility & Auth Manager
 */

// Global API Helper
async function apiCall(endpoint, method = 'GET', body = null) {
  const options = {
    method,
    headers: {}
  };

  if (body) {
    if (body instanceof FormData) {
      options.body = body;
    } else {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(body);
    }
  }

  try {
    const response = await fetch(endpoint, options);
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Request failed with status ' + response.status);
    }

    return data;
  } catch (err) {
    console.error(`API Error [${method} ${endpoint}]:`, err);
    throw err;
  }
}

// Authentication & Role Check
async function checkAuth(requiredRole = null) {
  try {
    const data = await apiCall('/api/auth/me');
    const user = data.user;

    // Display user info in sidebar if present
    const userNameElem = document.getElementById('user-name-display');
    const userRoleElem = document.getElementById('user-role-display');
    if (userNameElem) userNameElem.textContent = user.name;
    if (userRoleElem) userRoleElem.textContent = user.role;

    // Verify role matches current dashboard
    if (requiredRole && user.role !== requiredRole && user.role !== 'ADMIN') {
      redirectToRoleDashboard(user.role);
    }

    return user;
  } catch (err) {
    // If unauthenticated and not on auth pages, redirect to login
    const path = window.location.pathname;
    if (!path.endsWith('index.html') && !path.endsWith('register.html') && path !== '/' && path !== '/login' && path !== '/register') {
      window.location.href = '/index.html';
    }
    return null;
  }
}

// Redirect user to proper dashboard based on database role
function redirectToRoleDashboard(role) {
  if (role === 'ADMIN') {
    window.location.href = '/admin-dashboard.html';
  } else if (role === 'OWNER') {
    window.location.href = '/owner-dashboard.html';
  } else if (role === 'VIEWER') {
    window.location.href = '/viewer-dashboard.html';
  } else {
    window.location.href = '/index.html';
  }
}

// Global Logout Action
async function handleLogout() {
  try {
    await apiCall('/api/auth/logout', 'POST');
    window.location.href = '/index.html';
  } catch (err) {
    alert('Logout failed: ' + err.message);
  }
}

// Toast Notifications
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container') || createToastContainer();
  const toastElem = document.createElement('div');
  toastElem.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show shadow-sm`;
  toastElem.role = 'alert';
  toastElem.innerHTML = `
    <span>${message}</span>
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
  `;
  container.appendChild(toastElem);

  setTimeout(() => {
    toastElem.classList.remove('show');
    setTimeout(() => toastElem.remove(), 200);
  }, 4000);
}

function createToastContainer() {
  const container = document.createElement('div');
  container.id = 'toast-container';
  container.className = 'position-fixed bottom-0 end-0 p-3';
  container.style.zIndex = '9999';
  document.body.appendChild(container);
  return container;
}

// Format Utilities
function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDate(dateString) {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  return date.toLocaleString();
}
