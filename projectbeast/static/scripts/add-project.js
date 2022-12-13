$addProjectButton = $('#project-menu-button')
$addProjectModal = $('#add-project-modal')
$addProjectForm = $('#add-project-form')

$addProjectButton.on('click', showAddProject);

function showAddProject() {
    $addProjectModal.removeClass('hidden');
}