$addGroupButton = $('#add-group-button')
$addGroupModal = $('#add-group-modal')
$addGroupForm = $('#add-group-form')

$addGroupButton.on('click', showAddGroup);

function showAddGroup() {
    $addGroupModal.removeClass('hidden');
}

$(function () {
    $(".group-link").each(function () {
      if ($(this).prop("href") == window.location.href) {
        $(this).addClass("active2");
      }
    });
  });