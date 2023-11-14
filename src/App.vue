<script setup>
import { ref, computed } from 'vue'
import Home from './components/pages/Home.vue'
import Login from './components/pages/Login.vue'
import Register from './components/pages/Register.vue'
import Nav from './components/header/Nav.vue'
import About from './components/pages/About.vue'
import Contact from './components/pages/Contact.vue'
import Landing from './components/pages/Landing.vue'
import Profile from './components/pages/Profile.vue'
import Shoe from './components/pages/Shoe.vue'
import Footer from './components/footer/Footer.vue'
import Forgotpassword from './components/pages/Forgotpassword.vue'

const routes = {
  '/': Landing,
  '/login': Login,
  '/register': Register,
  '/about': About,
  '/contact': Contact,
  '/home': Home,
  '/profile': Profile,
  '/shoe': Shoe,
  '/forgot-password': Forgotpassword
}
let currentRoute = window.location.pathname;
// eslint-disable-next-line no-empty
if (currentRoute === "/"){
}

const currentPath = ref(window.location.hash)

window.addEventListener('hashchange', () => {
  currentPath.value = window.location.hash
})

const currentView = computed(() => {
  // eslint-disable-next-line no-undef
  return routes[currentPath.value.slice(1) || '/'] || NotFound
})
</script>

<template>
  <!-- <a href="#/">Home</a> |
  <a href="#/login">Login</a> |
  <a href="#/register">Register</a> -->
  <Nav />
  <component :is="currentView" />

  <Footer />
</template>