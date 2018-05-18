$(document).ready(function(){
    setDataTable()
    $("select").change(function(){
        makeQuery()
    })
    $("input.datepicker").change(function(){
        makeQuery()
    })
    $("input#search_term_large").keypress(function(e) {
        if(e.which == 13) {
            makeQuery()
        }
    });

});

function setDataTable(){
    $('table#data_table').DataTable({
        paging: true
    });
}

function getFilters(){
    var init_date = $("input[name='init_date']").val()
    var end_date = $("input[name='end_date']").val()
    var os_filter = $("select[id='os_filter']").val()
    var apps_filter = $("select[id='apps_filter']").val()
    var brand_filter = $("select[id='brand_filter']").val()
    var browser_filter = $("select[id='browser_filter']").val()
    var search_term = $("input[id='search_term_large']").val()
    
    data_filters = {}

    if (search_term.length > 0) { data_filters['search_term'] = search_term}
    if (init_date.length > 0) { data_filters['init_date'] = init_date}
    if (end_date.length > 0) { data_filters['end_date'] = end_date}
    if (os_filter.length > 0 && os_filter != '*') { data_filters['os'] = os_filter}
    if (apps_filter.length > 0 && apps_filter != '*') { data_filters['apps'] = apps_filter}
    if (brand_filter.length > 0 && brand_filter != '*') { data_filters['brand'] = brand_filter}
    if (browser_filter.length > 0 && browser_filter != '*') { data_filters['browser'] = browser_filter}
    
    return data_filters
}

function makeQuery(){

    var jqXhr = $.ajax({
        url: "/airprofiling/ajax/getResultsOfSearch",
        method: "GET",
        data: getFilters()
    });

    jqXhr
    .done(function(data) {
        $("#table_container").html(data.html);
        setDataTable()        
    })
    .fail(function(xhr) {
      console.log('error callback for true condition', xhr);
    });
}