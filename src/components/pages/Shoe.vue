<template>
  <div id="app">
    <Modal v-if="isModalOpen" @close="closeModal">
      <!-- Content of the modal goes here -->
      <div class="card">
        <form @submit.prevent="createShoe">
          <div class="form-group">
            <label for="brand">Brand</label>
            <input id="brand" v-model="brand" required>
            <div v-if="!brand" class="req">Brand is required!</div>
          </div>

          <div class="form-group">
            <label for="model">Model</label>
            <input id="model" v-model="model" required>
            <div v-if="!model" class="req">Model is required!</div>
          </div>

          <div class="form-group">
            <label for="size">Size</label>
            <input id="size" v-model="size" type="number" required>
            <div v-if="!size" class="req">Size is required!</div>
          </div>

          <div class="form-group">
            <label for="color">Color</label>
            <input id="color" v-model="color" required>
            <div v-if="!color" class="req">Color is required!</div>
          </div>

          <div class="form-group">
            <label for="price">Price</label>
            <input id="price" v-model="price" type="number" required>
            <div v-if="!price" class="req">Price is required!</div>
          </div>

          <button type="submit" :disabled="loading">Submit</button>
          <div v-if="loading">Loading...</div>
        </form>
        <button @click="closeModal" class="close-button">Close</button>
      </div>
    </Modal>

     <!-- Update Shoe Modal -->
     <Modal v-if="isUpdateModalOpen" @close="closeUpdateModal">
      <!-- Content of the modal goes here -->
      <div class="card">
        <form @submit.prevent="updateShoe">
          <!-- You can use the existing form fields with pre-filled data from selected shoe -->
          <div class="form-group">
            <label for="brand">Brand</label>
            <input id="brand" v-model="updatedBrand" required>
            <!-- <div v-if="!updatedBrand" class="req">Brand is required!</div> -->
          </div>

          <div class="form-group">
            <label for="model">Model</label>
            <input id="model" v-model="updatedModel" required>
            <!-- <div v-if="!model" class="req">Model is required!</div> -->
          </div>

          <div class="form-group">
            <label for="size">Size</label>
            <input id="size" v-model="updatedSize" type="number" required>
            <!-- <div v-if="!size" class="req">Size is required!</div> -->
          </div>

          <div class="form-group">
            <label for="color">Color</label>
            <input id="color" v-model="updatedColor" required>
            <!-- <div v-if="!color" class="req">Color is required!</div> -->
          </div>

          <div class="form-group">
            <label for="price">Price</label>
            <input id="price" v-model="updatedPrice" type="number" required>
            <!-- <div v-if="!price" class="req">Price is required!</div> -->
          </div>

          <button type="submit" :disabled="loading">Update</button>
          <div v-if="loading">Loading...</div>
        </form>
        <button @click="closeUpdateModal" class="close-button">Close</button>
      </div>
    </Modal>

    <section class="food_section layout_padding">
    <div class="container">
      <div class="heading_container heading_center">
        <h2>
          Our Shoes
        </h2>
      </div>

      <ul class="filters_menu">
        <li class="active" data-filter="*">All</li>
        <li data-filter=".burger"><b-button @click="openModal">Create Shoe</b-button></li>
      </ul>

      <div class="filters-content">
        <div class="row grid">
          <div class="col-sm-6 col-lg-4 all pizza" v-for="shoe in shoes" :key="shoe.id">
            <div class="box">
              <div>
                <div class="img-box">
                  <img :src="'https://images.pexels.com/photos/1456733/pexels-photo-1456733.jpeg?auto=compress&cs=tinysrgb&w=1260&h=750&dpr=1'" alt="Shoe Image" class="shoe-image">
                </div>
                <div class="detail-box">
                  <h5>
                    {{ shoe.model }}
                    {{ shoe.brand }}
                  </h5>
                  <p>
                    Veniam debitis quaerat officiis quasi cupiditate quo, quisquam velit, magnam voluptatem repellendus sed eaque
                    </p>
                    <p>Size: {{ shoe.size }} , Color: {{ shoe.color }}</p>
                  <div class="options">
                      <p>Price: ${{ shoe.price }}</p>
                  </div>
                  <button @click="confirmDelete(shoe.id)" class="delete">Delete</button>
                      <button @click="openUpdateModal(shoe)">Update</button>
                </div>
              </div>
            </div>
          </div>
        </div>
        </div>
        </div>
  </section>
  </div>
</template>


<script>
import axios from 'axios';

export default {
  // eslint-disable-next-line vue/multi-word-component-names
  name: 'Shoe',

  data() {
    return {
      isModalOpen: false,
      brand: '',
      model: '',
      size: null,
      color: '',
      price: null,
      loading: false,
      shoes: [],
      isUpdateModalOpen: false,
      updatedBrand: '',
      updatedModel: '',
      updatedSize: null,
      updatedColor: '',
      updatedPrice: null,
      selectedShoe: null,
    };
  },

  created() {
    this.fetchShoes();
  },

  methods: {
    fetchShoes() {
      axios.get('http://localhost:8080/showAll')
        .then(response => {
          this.shoes = response.data;
        })
        .catch(error => {
          console.error('Error fetching shoe data:', error);
          this.error = 'Error fetching shoe data. Please try again later.';
        });
    },

    openModal() {
      // Close the update modal if it is open
      if (this.isUpdateModalOpen) {
        this.closeUpdateModal();
      }

      this.isModalOpen = true;
      this.scrollToTop();
    },

    closeModal() {
      this.isModalOpen = false;
    },

    scrollToTop() {
      window.scrollTo({
        top: 0,
        behavior: 'smooth',
      });
    },

    createShoe() {
      this.loading = true;

      const shoeData = {
        brand: this.brand,
        model: this.model,
        size: this.size,
        color: this.color,
        price: this.price,
      };

      axios.post('http://localhost:8080/create', shoeData)
        .then(response => {
          console.log('Success:', response.data);
          window.alert("Shoe added successfully");
          window.location.reload();
        })
        .catch(error => {
          console.error('Error:', error);
          window.alert("Error adding shoe. Please try again.");
        })
        .finally(() => {
          this.loading = false;
          this.closeModal();
        });
    },

    confirmDelete(shoeId) {
      if (confirm("Are you sure you want to delete this shoe?")) {
        // User clicked OK, proceed with deletion
        this.deleteShoe(shoeId);
      } else {
        // User clicked Cancel, do nothing
      }
    },

    deleteShoe(shoeId) {
      this.loading = true;

      axios.delete(`http://localhost:8080/delete/${shoeId}`)
        .then(response => {
          console.log('Success:', response.data);
          window.alert("Shoe deleted successfully");
          window.location.reload();
        })
        .catch(error => {
          console.error('Error:', error);
          window.alert("Error deleting shoe. Please try again.");
        })
        .finally(() => {
          this.loading = false;
        });
    },

    openUpdateModal(shoe) {
      // Close the create modal if it is open
      if (this.isModalOpen) {
        this.closeModal();
      }

      // Populate the data properties with the selected shoe's data
      this.updatedBrand = shoe.brand;
      this.updatedModel = shoe.model;
      this.updatedSize = shoe.size;
      this.updatedColor = shoe.color;
      this.updatedPrice = shoe.price;

      // Store the selected shoe for later use
      this.selectedShoe = shoe;

      this.isUpdateModalOpen = true;
      this.scrollToTop();
    },

    closeUpdateModal() {
      // Clear the data properties when closing the update modal
      this.updatedBrand = '';
      this.updatedModel = '';
      this.updatedSize = null;
      this.updatedColor = '';
      this.updatedPrice = '';

      // Clear the selected shoe
      this.selectedShoe = null;

      this.isUpdateModalOpen = false;
    },

    updateShoe() {
      this.loading = true;

      const shoeData = {
        brand: this.updatedBrand,
        model: this.updatedModel,
        size: this.updatedSize,
        color: this.updatedColor,
        price: this.updatedPrice,
      };

      axios.put(`http://localhost:8080/update/${this.selectedShoe.id}`, shoeData)
        .then(response => {
          console.log('Success:', response.data);
          window.alert("Shoe updated successfully");
          window.location.reload();
        })
        .catch(error => {
          console.error('Error:', error);
          window.alert("Error updating shoe. Please try again.");
        })
        .finally(() => {
          this.loading = false;
          this.closeUpdateModal();
        });
    },
  },
};
</script>




<style scoped>
  /* Add your modal styles here */
  .modal {
    display: none;
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 9999;
    background-color: rgba(0, 0, 0, 0.4);
    width: 100%;
    height: 100%;
    overflow: auto;
  }

  .modal-create-shoe {
    z-index: 10000;
  }

  .modal-update-shoe {
    z-index: 10001;
  }

  /* Card styles */
  .card {
    background-color: #fefefe;
    margin: 5% auto;
    padding: 20px;
    border: 1px solid #888;
    width: 80%;
    max-width: 600px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    border-radius: 8px;
  }

  .close-button {
    color: #aaa;
    float: right;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
    border: none;
    background: none;
  }

  .close-button:hover {
    color: black;
  }

  .form-group {
    margin-bottom: 20px;
  }

  label {
    display: block;
    margin-bottom: 8px;
    font-weight: bold;
  }

  input {
    width: 100%;
    padding: 8px;
    box-sizing: border-box;
    margin-bottom: 8px;
  }

  .error-message {
    color: red;
    margin-top: 4px;
  }

  button {
    background-color: #4caf50;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    float: right;
    margin: 0px 5px 15px 5px;
  }

  .delete{
    background-color: red;
    color: white;
    padding: 10px 15px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
  }

  button:disabled {
    background-color: #ccc;
    cursor: not-allowed;
  }

  .loading {
    margin-top: 10px;
  }

  .req {
    color: red;
  }

  .food_section .filters_menu {
  padding: 0;
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -ms-flex-wrap: wrap;
      flex-wrap: wrap;
  -webkit-box-pack: center;
      -ms-flex-pack: center;
          justify-content: center;
  list-style-type: none;
  margin: 45px 0 20px 0;
}

.food_section .filters_menu li {
  padding: 7px 25px;
  cursor: pointer;
  border-radius: 25px;
}

.food_section .filters_menu li.active {
  background-color: #222831;
  color: #ffffff;
}

.food_section .box {
  position: relative;
  margin-top: 25px;
  background-color: #ffffff;
  border-radius: 10px;
  color: #ffffff;
  border-radius: 15px;
  overflow: hidden;
  background: linear-gradient(to bottom, #f1f2f3 25px, #222831 25px);
}

.food_section .box .img-box {
  background: #f1f2f3;
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: center;
      -ms-flex-pack: center;
          justify-content: center;
  -webkit-box-align: center;
      -ms-flex-align: center;
          align-items: center;
  height: 215px;
  border-radius: 0 0 0 45px;
  margin: -1px;
  padding: 25px;
}

.food_section .box .img-box img {
  max-width: 100%;
  max-height: 100%;
  -webkit-transition: all .2s;
  transition: all .2s;
}

.food_section .box .detail-box {
  padding: 25px;
}

.food_section .box .detail-box h5 {
  font-weight: 600;
}

.food_section .box .detail-box p {
  font-size: 15px;
}

.food_section .box .detail-box h6 {
  margin-top: 10px;
}

.food_section .box .options {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: justify;
      -ms-flex-pack: justify;
          justify-content: space-between;
}

.food_section .box .options a {
  width: 40px;
  height: 40px;
  border-radius: 100%;
  background: #ffbe33;
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

.food_section .box .options a svg {
  width: 18px;
  height: auto;
  fill: #ffffff;
}

.food_section .box:hover .img-box img {
  -webkit-transform: scale(1.1);
          transform: scale(1.1);
}

.food_section .btn-box {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: center;
      -ms-flex-pack: center;
          justify-content: center;
  margin-top: 45px;
}

.food_section .btn-box a {
  display: inline-block;
  padding: 10px 55px;
  background-color: #ffbe33;
  color: #ffffff;
  border-radius: 45px;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
  border: none;
}

.food_section .btn-box a:hover {
  background-color: #e69c00;
}
li[data-filter=".burger"] b-button:hover {
    color: #fefefe; /* Replace with your desired hover color */
    background-color: #222831; /* Replace with your desired hover background color */
    padding: 7px 10px;
  cursor: pointer;
  border-radius: 25px;
  }
  /* Add more styles as needed */
</style>
