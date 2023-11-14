import { createRouter, createWebHistory } from 'vue-router';
import Home from './components/pages/Home.vue';
import Login from './components/pages/Login.vue';
import Register from './components/pages/Register.vue';
import About from './components/pages/About.vue';
import Contact from './components/pages/Contact.vue';
import Landing from './components/pages/Landing.vue';
import Profile from './components/pages/Profile.vue';
import Shoe from './components/pages/Shoe.vue';

const routes = [
  { path: '/', component: Landing },
  { path: '/login', component: Login },
  { path: '/register', component: Register },
  { path: '/about', component: About },
  { path: '/contact', component: Contact },
  { path: '/home', component: Home, meta: { requiresAuth: true } }, // Add meta field for authentication
  { path: '/profile', component: Profile, meta: { requiresAuth: true } },
  { path: '/shoe', component: Shoe, meta: { requiresAuth: true } },
  { path: '/forgot-password', component: Shoe, meta: { requiresAuth: true } },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to, from, next) => {
  const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';

  if (to.meta.requiresAuth && !isLoggedIn) {
    // If the route requires authentication and the user is not logged in, redirect to the login page
    next('/login');
  } else {
    // If the route does not require authentication or the user is logged in, proceed with the navigation
    next();
  }
});

export default router;
