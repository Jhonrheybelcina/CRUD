<template>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container">
        <a class="navbar-brand" href="#">ShoeLit</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
          <ul class="navbar-nav">
            <li class="nav-item">
              <a v-if="isLoggedIn" class="nav-link" href="#/home">Home</a>
            </li>
            <li class="nav-item">
                <a v-if="isLoggedIn" class="nav-link" href="#/shoe">Shoe</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="#/about">About</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="#/contact">Contact</a>
            </li>
            <li class="nav-item">
              <a v-if="!isLoggedIn" class="nav-link" href="#/login">Login</a>
            </li>
            <li class="nav-item">
              <a v-if="!isLoggedIn" class="nav-link" href="#/register">Sign Up</a>
            </li>
            <li class="nav-item">
              <a v-if="isLoggedIn" class="nav-link" href="#/profile">Profile</a>
            </li>
            <li class="nav-item">
                <a v-if="isLoggedIn" class="nav-link" @click="logout">Log out</a>
            </li>
          </ul>
        </div>
      </div>
    </nav>
  </template>
  
  <script>
  import { useRouter } from 'vue-router';
  export default {

    // eslint-disable-next-line vue/multi-word-component-names
    name: 'Nav',
    data() {
      return {
        isLoggedIn: false,
      };
    },
    mounted() {
      // Check the local storage for the 'isLoggedIn' key
      const isLoggedIn = localStorage.getItem('isLoggedIn');
      if (isLoggedIn && isLoggedIn === 'true') {
        // If 'isLoggedIn' is true in local storage, set the data property to true
        this.isLoggedIn = true;
      } else {
        // If 'isLoggedIn' is not true or not found in local storage, set the data property to false
        this.isLoggedIn = false;
      }
    },
    methods: {
      logout() {
        // eslint-disable-next-line no-unused-vars
        const router = useRouter();
        // Clear the 'isLoggedIn' key from local storage
        localStorage.clear();
  
        // Use Vue Router's push method to navigate to the landing page
        window.location.href='#/' // Assuming the landing page path is '/'
  
        // Optionally, you can also reload the page if needed
        window.location.reload();
      },
    },
  };
  </script>