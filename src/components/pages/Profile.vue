<template>
    <h1>Profile</h1>
</template>

<script>
export default {
    // eslint-disable-next-line vue/multi-word-component-names
    name: 'Profile',
    mounted() {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';

    if (!isLoggedIn) {
      // If user is not logged in, show an alert, deny access, and redirect to the login page
      alert('Access Denied. Please log in.');
      window.location.href='#/login' // Assuming the login page path is '/login'
    }
  },
}
</script>