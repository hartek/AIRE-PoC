$(document).ready(function(){
    setDataTable()
});

function setDataTable(){
    $('table#data_table').DataTable({
        paging: true
    });
}