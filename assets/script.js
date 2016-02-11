$(function() {
  $('#persona-form').submit(function(e) {
    if (!$('#persona-assertion').val()) {
      e.preventDefault();
      navigator.id.get(function(assertion) {
        if (assertion) {
          $('#persona-assertion').val(assertion);
          $('#persona-form').submit();
        } else {
          location.reload();
        }
      });
    }
  });
});
