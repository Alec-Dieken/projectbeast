$addTaskButton = $('#task-menu-button')
$addTaskModal = $('#add-task-modal')
$addTaskForm = $('#add-task-form')

$taskLink = $('.task-item')

$addTaskButton.on('click', showAddTask);

function showAddTask() {
    $addTaskModal.removeClass('hidden');
}

$taskLink.on('click', getTaskPage)

function getTaskPage(e) {
    id = $(this).data("task-id");
    window.location.href = `/task/${id}`;
}