$addTaskButton = $('#task-menu-button')
$addTaskModal = $('#add-task-modal')
$addTaskForm = $('#add-task-form')

$addTaskButton.on('click', showAddTask);

function showAddTask() {
    $addTaskModal.removeClass('hidden');
}