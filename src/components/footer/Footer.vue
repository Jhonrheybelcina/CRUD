<!-- eslint-disable vue/valid-template-root -->
<template>
<footer class="footer_section">
    <div class="container">
      <div class="row">
        <div class="col-md-4 footer-col">
          <div class="footer_contact">
            <h4>
              Contact Us
            </h4>
            <div class="contact_link_box">
              <a href="">
                <i class="fa fa-map-marker" aria-hidden="true"></i>
                <span>
                  Location
                </span>
              </a>
              <a href="">
                <i class="fa fa-phone" aria-hidden="true"></i>
                <span>
                  Call +01 1234567890
                </span>
              </a>
              <a href="">
                <i class="fa fa-envelope" aria-hidden="true"></i>
                <span>
                  demo@gmail.com
                </span>
              </a>
            </div>
          </div>
        </div>
        <div class="col-md-4 footer-col">
          <div class="footer_detail">
            <p class="footer-logo">
              ShoeLit
            </p>
            <p>
              Necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with
            </p>
            <div class="footer_social">
              <a href="">
                <i class="fa fa-facebook" aria-hidden="true"></i>
              </a>
              <a href="">
                <i class="fa fa-twitter" aria-hidden="true"></i>
              </a>
              <a href="">
                <i class="fa fa-linkedin" aria-hidden="true"></i>
              </a>
              <a href="">
                <i class="fa fa-instagram" aria-hidden="true"></i>
              </a>
              <a href="">
                <i class="fa fa-pinterest" aria-hidden="true"></i>
              </a>
            </div>
          </div>
        </div>
        <div class="col-md-4 footer-col">
          <h4>
            Opening Hours
          </h4>
          <p>
            Everyday
          </p>
          <p>
            10.00 Am -10.00 Pm
          </p>
        </div>
      </div>
      <div class="footer-info">
        <p>
          &copy; <span id="displayYear"></span> All Rights Reserved 
          <a href="https://html.design/">2023</a><br><br>
          &copy; <span id="displayYear"></span> Distributed By
          <a href="https://themewagon.com/" target="_blank">ThemeWagon</a>
        </p>
      </div>
    </div>
  </footer>

</template>

<script>
export default {
    // eslint-disable-next-line vue/multi-word-component-names
    name: 'Footer'
}

</script>

<style>
.footer_section {
  background-color: #222831;
  color: #ffffff;
  padding: 75px 0 40px 0;
  text-align: center;
}

.footer_section h4 {
  font-size: 28px;
}

.footer_section h4,
.footer_section .footer-logo {
  font-weight: 600;
  margin-bottom: 20px;
  font-family: 'Dancing Script', cursive;
}

.footer_section p {
  color: #dbdbdb;
}

.footer_section .footer-col {
  margin-bottom: 30px;
}

.footer_section .footer_contact .contact_link_box {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-orient: vertical;
  -webkit-box-direction: normal;
      -ms-flex-direction: column;
          flex-direction: column;
}

.footer_section .footer_contact .contact_link_box a {
  margin: 5px 0;
  color: #ffffff;
}

.footer_section .footer_contact .contact_link_box a i {
  margin-right: 5px;
}

.footer_section .footer_contact .contact_link_box a:hover {
  color: #ffbe33;
}

.footer_section .footer-logo {
  display: block;
  font-weight: bold;
  font-size: 38px;
  line-height: 1;
  color: #ffffff;
}

.footer_section .footer_social {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: center;
      -ms-flex-pack: center;
          justify-content: center;
  margin-top: 20px;
  margin-bottom: 10px;
}

.footer_section .footer_social a {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: center;
      -ms-flex-pack: center;
          justify-content: center;
  -webkit-box-align: center;
      -ms-flex-align: center;
          align-items: center;
  color: #222831;
  width: 30px;
  height: 30px;
  border-radius: 100%;
  background-color: #ffffff;
  border-radius: 100%;
  margin: 0 2.5px;
  font-size: 18px;
}

.footer_section .footer_social a:hover {
  color: #ffbe33;
}

.footer_section .footer-info {
  text-align: center;
  margin-top: 25px;
}

.footer_section .footer-info p {
  color: #ffffff;
  margin: 0;
}

.footer_section .footer-info p a {
  color: inherit;
}
</style>