<template>
    <!-- <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container">
        <a class="navbar-brand" href="#">ShoeLit</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
          <ul class="navbar-nav">
            <li class="nav-item">
              <a class="nav-link" href="#/">Home</a>
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
    </nav> -->
    
    <header class="header_section">
      <div class="container">
        <nav class="navbar navbar-expand-lg custom_nav-container ">
          <a class="navbar-brand" href="index.html">
            <span>
              Shoelit
            </span>
          </a>

          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
            <span class=""> </span>
          </button>

          <div class="collapse navbar-collapse" id="navbarSupportedContent">
            <ul class="navbar-nav  mx-auto ">
              <li class="nav-item active">
                <a class="nav-link" href="#/">Home <span class="sr-only">(current)</span></a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#/shoe"  v-if="isLoggedIn">Shoe</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#/about">About</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#/contact">Contact</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#/login" v-if="!isLoggedIn">Login</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#/register" v-if="!isLoggedIn">Register</a>
              </li>
            </ul>
            <div class="user_option"  v-if="isLoggedIn">
              <a href="#/profile" class="user_link">
                <i class="fa fa-user" aria-hidden="true"></i>
              </a>
              <a class="user_link" @click="logout">
                <i class="fa fa-sign-out" aria-hidden="true"></i>
              </a>
              <form class="form-inline">
                <button class="btn  my-2 my-sm-0 nav_search-btn" type="submit">
                  <i class="fa fa-search" aria-hidden="true"></i>
                </button>
              </form>
              <a href="" class="order_online">
                Order Online
              </a>
            </div>
          </div>
        </nav>
      </div>
    </header>
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
        window.location.href='#/login' // Assuming the landing page path is '/'
  
        // Optionally, you can also reload the page if needed
        window.location.reload();
      },
    },
  };
  </script>

  <style scoped>

.header_section {
  padding: 15px 0;
  background-color: black;
}

.header_section .container-fluid {
  padding-right: 25px;
  padding-left: 25px;
}

.navbar-brand {
  font-family: 'Dancing Script', cursive;
}

.navbar-brand span {
  font-weight: bold;
  font-size: 32px;
  color: #ffffff;
}

.custom_nav-container {
  padding: 0;
}

.custom_nav-container .navbar-nav {
  padding-left: 18%;
}

.custom_nav-container .navbar-nav .nav-item .nav-link {
  padding: 5px 20px;
  color: #ffffff;
  text-align: center;
  text-transform: uppercase;
  border-radius: 5px;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
}

.custom_nav-container .navbar-nav .nav-item:hover .nav-link, .custom_nav-container .navbar-nav .nav-item.active .nav-link {
  color: #ffbe33;
}

.custom_nav-container .nav_search-btn {
  width: auto;
  height: auto;
  padding: 0;
  border: none;
  color: #ffffff;
  margin: 0 10px;
}

.custom_nav-container .nav_search-btn:hover {
  color: #ffbe33;
}

.user_option {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-align: center;
      -ms-flex-align: center;
          align-items: center;
}

.user_option a {
  margin: 0 10px;
}

.user_option .user_link {
  color: #ffffff;
}

.user_option .user_link:hover {
  color: #ffbe33;
}

.user_option .cart_link {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: center;
      -ms-flex-pack: center;
          justify-content: center;
  -webkit-box-align: center;
      -ms-flex-align: center;
          align-items: center;
}

.user_option .cart_link svg {
  width: 17px;
  height: auto;
  fill: #ffffff;
  margin-bottom: 2px;
}

.user_option .cart_link:hover svg {
  fill: #ffbe33;
}

.user_option .order_online {
  display: inline-block;
  padding: 8px 30px;
  background-color: #ffbe33;
  color: #ffffff;
  border-radius: 45px;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
  border: none;
}

.user_option .order_online:hover {
  background-color: #e69c00;
}

.custom_nav-container .navbar-toggler {
  outline: none;
}

.custom_nav-container .navbar-toggler {
  padding: 0;
  width: 37px;
  height: 42px;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
}

.custom_nav-container .navbar-toggler span {
  display: block;
  width: 35px;
  height: 4px;
  background-color: #ffffff;
  margin: 7px 0;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
  position: relative;
  border-radius: 5px;
  transition: all 0.3s;
}

.custom_nav-container .navbar-toggler span::before, .custom_nav-container .navbar-toggler span::after {
  content: "";
  position: absolute;
  left: 0;
  height: 100%;
  width: 100%;
  background-color: #ffffff;
  top: -10px;
  border-radius: 5px;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
}

.custom_nav-container .navbar-toggler span::after {
  top: 10px;
}

.custom_nav-container .navbar-toggler[aria-expanded="true"] {
  -webkit-transform: rotate(360deg);
          transform: rotate(360deg);
}

.custom_nav-container .navbar-toggler[aria-expanded="true"] span {
  -webkit-transform: rotate(45deg);
          transform: rotate(45deg);
}

.custom_nav-container .navbar-toggler[aria-expanded="true"] span::before, .custom_nav-container .navbar-toggler[aria-expanded="true"] span::after {
  -webkit-transform: rotate(90deg);
          transform: rotate(90deg);
  top: 0;
}


</style>