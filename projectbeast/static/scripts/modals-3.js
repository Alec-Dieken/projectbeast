$(document).on('mousedown', handleModal);
$modalContainer = $('.modal-project-container')

function handleModal(e) {

    if(typeof $addProjectButton !== 'undefined' && !$addProjectButton.is(e.target)) {
        if(!$modalContainer.is(e.target) && $modalContainer.has(e.target).length === 0) {
            $addProjectModal.addClass('hidden');
        }
    }
    if(typeof $addTaskButton !== 'undefined' && !$addTaskButton.is(e.target)) {
        if(!$modalContainer.is(e.target) && $modalContainer.has(e.target).length === 0) {
            $addTaskModal.addClass('hidden');
        }
    }
    if(typeof $addGroupButton !== 'undefined' && !$addGroupButton.is(e.target)) {
        if(!$modalContainer.is(e.target) && $modalContainer.has(e.target).length === 0) {
            $addGroupModal.addClass('hidden');
        }
    }
    if(typeof $addGroupMemberIcon !== 'undefined' && !$addGroupMemberIcon.is(e.target)) {
        if(!$addGroupMemberForm.is(e.target) && $addGroupMemberForm.has(e.target).length === 0) {
            $addGroupMemberModal.addClass('hidden');
        }
    }
}