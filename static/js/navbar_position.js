window.addEventListener('scroll', function() {
  var navbar = document.querySelector('.navbar');
  var offset = window.pageYOffset;

  if (offset > 0) {
    navbar.classList.add('fixed');
  } else {
    navbar.classList.remove('fixed');
  }
});

const title = "Привет!";
let i = 0;
