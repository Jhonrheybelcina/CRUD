<!-- eslint-disable vue/multi-word-component-names -->
<template>
<section class="book_section layout_padding">
    <div class="container">
      <div class="heading_container">
        <h2>
          Contact Us
        </h2>
      </div>
      <div class="row">
        <div class="col-md-6">
          <div class="form_container">
            <form action="">
              <div>
                <input type="text" class="form-control" placeholder="Your Name" />
              </div>
              <div>
                <input type="text" class="form-control" placeholder="Phone Number" />
              </div>
              <div>
                <input type="email" class="form-control" placeholder="Your Email" />
              </div>
              <div>
                <select class="form-control nice-select wide">
                  <option value="" disabled selected>
                    Ratings?
                  </option>
                  <option value="">
                    2
                  </option>
                  <option value="">
                    3
                  </option>
                  <option value="">
                    4
                  </option>
                  <option value="">
                    5
                  </option>
                </select>
              </div>
              <div>
                <input type="date" class="form-control">
              </div>
              <div class="btn_box">
                <button>
                  Contact now
                </button>
              </div>
            </form>
          </div>
        </div>
        <div class="col-md-6">
          <div class="map_container ">
            <div id="googleMap">
                <iframe src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3925.043940434459!2d123.90911057503571!3d10.33836878978501!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x33a998e133925eeb%3A0xfeda037a6ba9d730!2sUniversity%20of%20Cebu%20-%20Banilad%20Campus!5e0!3m2!1sen!2sph!4v1699513727306!5m2!1sen!2sph" width="600" height="450" style="border:0;" allowfullscreen="" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>
            </div>
            
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script>

</script>

<style scoped>
@import url("https://fonts.googleapis.com/css2?family=Dancing+Script:wght@400;500;600;700&family=Open+Sans:wght@400;600;700&display=swap");
body {
  font-family: "Open Sans", sans-serif;
  color: #0c0c0c;
  background-color: #ffffff;
  overflow-x: hidden;
}

.layout_padding {
  padding: 90px 0;
}

.layout_padding2 {
  padding: 75px 0;
}

.layout_padding2-top {
  padding-top: 75px;
}

.layout_padding2-bottom {
  padding-bottom: 75px;
}

.layout_padding-top {
  padding-top: 90px;
}

.layout_padding-bottom {
  padding-bottom: 90px;
}

h1,
h2 {
  font-family: 'Dancing Script', cursive;
}

.heading_container {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-orient: vertical;
  -webkit-box-direction: normal;
      -ms-flex-direction: column;
          flex-direction: column;
  -webkit-box-align: start;
      -ms-flex-align: start;
          align-items: flex-start;
}

.heading_container h2 {
  position: relative;
  margin-bottom: 0;
  font-size: 2.5rem;
  font-weight: bold;
}

.heading_container h2 span {
  color: #ffbe33;
}

.heading_container p {
  margin-top: 10px;
  margin-bottom: 0;
}

.heading_container.heading_center {
  -webkit-box-align: center;
      -ms-flex-align: center;
          align-items: center;
  text-align: center;
}

.book_section {
  position: relative;
}

.book_section .heading_container {
  margin-bottom: 25px;
}

.book_section .form_container .form-control {
  width: 100%;
  border: none;
  height: 50px;
  margin-bottom: 25px;
  padding-left: 25px;
  border: 1px solid #999;
  outline: none;
  color: #000000;
  border-radius: 5px;
  outline: none;
  -webkit-box-shadow: none;
          box-shadow: none;
}

.book_section .form_container .form-control::-webkit-input-placeholder {
  color: #222222;
}

.book_section .form_container .form-control:-ms-input-placeholder {
  color: #222222;
}

.book_section .form_container .form-control::-ms-input-placeholder {
  color: #222222;
}

.book_section .form_container .form-control::placeholder {
  color: #222222;
}

.book_section .form_container .nice-select .current {
  font-size: 16px;
}

.book_section .form_container button {
  margin-top: 15px;
  border: none;
  text-transform: uppercase;
  display: inline-block;
  padding: 10px 55px;
  background-color: #ffbe33;
  color: #ffffff;
  border-radius: 45px;
  -webkit-transition: all 0.3s;
  transition: all 0.3s;
  border: none;
}

.book_section .form_container button:hover {
  background-color: #e69c00;
}

.book_section .map_container {
  width: 100%;
  height: 345px;
  border-radius: 10px;
  overflow: hidden;
}

.book_section .map_container #googleMap {
  height: 100%;
  min-height: 100%;
  width: 100%;
}



/*# sourceMappingURL=style.css.map */

</style>