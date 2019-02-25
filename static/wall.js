$(document).ready(function () {
    /* USERNAME AVAILABILITY */
    $('#usernames').keyup(function () {
        var data = $("#regForm").serialize()
        // capture all the data in the form in the variable data
        $.ajax({
            method: "POST",   // we are using a post request here, but this could also be done with a get
            url: "/username",
            data: data
        }
        )
            .done(function (res) {
                $('#usernameMsg').html(res)  // manipulate the dom when the response comes back
            })
    })
    $('#search_bar').keyup(function () {
        var data = $('#search_bar_form').serialize()

        $.ajax({
            method: 'get',
            url: '/usersearch',
            data: data
        }
        )
            .done(function (res) {
                $('#search_bar_output').html(res)
            })
        })
})


    