jQuery(function () {
    let table = new DataTable('#table');
    $("#start").click(function () {
        let interface = $("#interface").val();
        var socket = new WebSocket("ws://127.0.0.1:8000/ws/sniff/" + interface)
        socket.onmessage = function (e) {
            var data = JSON.parse(e.data);
            if (data.type == "packet") {
                table.row.add([data.time, data.packet, data.raw_packet]).draw(false);
            } else {
                $("#alert").text("Найдена сигнатура " + data.name);
                console.log("show")
                $('#exampleModal').modal('show');
            }

        }

        $("#stop").click(function () {
            socket.close();
        })
    })

})