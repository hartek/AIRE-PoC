$(document).ready(function(){
    $('table#apps_table').DataTable({
      paging: true
    });
    $('table#webpages_table').DataTable({
      paging: true
    });

    loadHtmlOfTimeline()
    $("select").change(function(){
        loadHtmlOfTimeline()
    })
    $("input.datepicker").change(function(){
        loadHtmlOfTimeline()
    })
    $("input#search_term_large").keypress(function(e) {
        if(e.which == 13) {
            loadHtmlOfTimeline()
        }
    });
})


function loadHtmlOfTimeline(){
    var idTarget = $("#idTarget").val()
    var jqXhr = $.ajax({
        url: "/airprofiling/ajax/getTimelineFiltered/"+idTarget,
        method: "GET",
        data: getFilters()
    });
    $("#timeline_container").html('');
    
    jqXhr
    .done(function(data) {
        $("#timeline_container").html(data.html);
    })
    .fail(function(xhr) {
        console.log('error callback for true condition', xhr);
    });
}


function getFilters(){
    var search_term = $("input[id='search_term_large']").val()
    var init_date = $("input[name='init_date']").val()
    var end_date = $("input[name='end_date']").val()
    var apps_filter = $("select[id='apps_filter']").val()
    var webpages_filter = $("select[id='webpages_filter']").val()

    data_filters = {}

    if (search_term.length > 0) { data_filters['search_term'] = search_term}
    if (init_date.length > 0) { data_filters['init_date'] = init_date}
    if (end_date.length > 0) { data_filters['end_date'] = end_date}
    if (apps_filter.length > 0 && apps_filter != '*') { data_filters['apps'] = apps_filter}
    if (webpages_filter.length > 0 && webpages_filter != '*') { data_filters['webpages'] = webpages_filter}

    return data_filters
}