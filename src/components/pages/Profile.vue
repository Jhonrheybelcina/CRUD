<template>
  <!-- <div class="facebook-profile">
    <h1>Facebook Profile</h1>
    <div class="profile-info" v-if="user">
      <div class="profile-header">
        <div class="profile-picture">
          <i class="fas fa-user-circle fa-5x"></i> 
        </div>
        <h2>{{ user.username }}</h2>
      </div>
      <div class="profile-details">
        <div class="profile-item">
          <span class="label">Username:</span>
          <span class="value">{{ user.username }}</span>
        </div>
        <div class="profile-item">
          <span class="label">Email:</span>
          <span class="value">{{ user.email }}</span>
        </div>

      </div>
    </div>
    <div class="profile-not-found" v-else>
      <p>User not found</p>
    </div>
  </div> -->
  <div class="container mt-5" v-if="user">
    
    <div class="row d-flex justify-content-center">
        
        <div class="col-md-7">
            
            <div class="card p-3 py-4">
                
                <div class="text-center">
                    <img src="https://i.imgur.com/bDLhJiP.jpg" width="100" class="rounded-circle">
                </div>
                
                <div class="text-center mt-3">
                    <span class="bg-secondary p-1 px-4 rounded text-white">Pro</span>
                    <h5 class="mt-2 mb-0">{{ user.username }}</h5>
                    <span>{{ user.email }}</span>
                    
                    <div class="px-4 mt-1">
                        <p class="fonts">Consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. </p>
                    
                    </div>
                    
                     <ul class="social-list">
                        <li><i class="fa fa-facebook"></i></li>
                        <li><i class="fa fa-dribbble"></i></li>
                        <li><i class="fa fa-instagram"></i></li>
                        <li><i class="fa fa-linkedin"></i></li>
                        <li><i class="fa fa-google"></i></li>
                    </ul>
                    
                    <!-- <div class="buttons">
                        
                        <button class="btn btn-outline-primary px-4">Message</button>
                        <button class="btn btn-primary px-4 ms-3">Contact</button>
                    </div> -->
                    
                    
                </div>
                
               
                
                
            </div>
            
        </div>
        
    </div>
    
</div>
</template>
<script>
import axios from 'axios';

export default {
  // eslint-disable-next-line vue/multi-word-component-names
  name: 'Profile',
  data() {
    return {
      user: null,
    };
  },
  mounted() {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const userId = localStorage.getItem('userId'); // Assuming userId is stored after login

    if (!isLoggedIn) {
      // Redirect to login if not logged in
      this.$router.push('/login');
    } else {
      if (userId) {
        this.fetchUserProfile(userId);
      } else {
        console.error('User ID not found');
        this.user = null; // Reset user data
      }
    }
  },
  methods: {
    fetchUserProfile(userId) {
      axios.get(`http://localhost:8080/profile/${userId}`)
        .then(response => {
          this.user = response.data;
        })
        .catch(error => {
          console.error('Error fetching user profile:', error);
          this.user = null; // Reset user data
        });
    },
  },
};
</script>

<style>

body{
    background:#eee;
}

.card{
    border:none;
    position:relative;
    overflow:hidden;
    border-radius:8px;
    cursor:pointer;
    margin-bottom: 50px;
}

.card:before{
    
    content:"";
    position:absolute;
    left:0;
    top:0;
    width:4px;
    height:100%;
    background-color:#E1BEE7;
    transform:scaleY(1);
    transition:all 0.5s;
    transform-origin: bottom
}

.card:after{
    
    content:"";
    position:absolute;
    left:0;
    top:0;
    width:4px;
    height:100%;
    background-color:#8E24AA;
    transform:scaleY(0);
    transition:all 0.5s;
    transform-origin: bottom
}

.card:hover::after{
    transform:scaleY(1);
}


.fonts{
    font-size:11px;
}

.social-list{
    display:flex;
    list-style:none;
    justify-content:center;
    padding:0;
}

.social-list li{
    padding:10px;
    color:#8E24AA;
    font-size:19px;
}

/* 
.buttons button:nth-child(1){
       border:1px solid #8E24AA !important;
       color:#8E24AA;
       height:40px;
}

.buttons button:nth-child(1):hover{
       border:1px solid #8E24AA !important;
       color:#fff;
       height:40px;
       background-color:#8E24AA;
}

.buttons button:nth-child(2){
       border:1px solid #8E24AA !important;
       background-color:#8E24AA;
       color:#fff;
        height:40px;
} */
</style>