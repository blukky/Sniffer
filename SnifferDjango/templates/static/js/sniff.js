jQuery(function () {

    var btnBool = false
    var isStart = false;
    $(".power-button").click(function () {
        if (!btnBool) {
            $("#flexSwitchCheckDefault3").prop('checked', true);
            $("#flexSwitchCheckDefault2").prop('checked', true);
            $("#flexSwitchCheckDefault1").prop('checked', true);
            btnBool = true;
            if (!isStart) {
                start();
                isStart = true;
            }
        } else {
            $("#flexSwitchCheckDefault3").prop('checked', false);
            $("#flexSwitchCheckDefault2").prop('checked', false);
            $("#flexSwitchCheckDefault1").prop('checked', false);
            btnBool = false;
        }
    })

    function start() {
        console.log("Start")
        let interface = $("#interface").val();
        var socket = new WebSocket("ws://127.0.0.1:8000/ws/sniff/" + interface)
        socket.onmessage = function (e) {
            var data = JSON.parse(e.data);
            if (data.type == "packet") {
                table.row.add([data.time, data.packet, data.raw_packet]).draw(false);
            } else {
                if (btnBool) {
                    $("#alert").text("Найдена сигнатура " + data.name);
                    console.log("show")
                    $('#exampleModal').modal('show');
                }
            }

        }
        $("#stop").click(function () {
            socket.send("close");
            socket.close();
        })
    }

    let table = new DataTable('#table');
    $("#start").click(function () {
        if (!isStart) {
            start();
            isStart = true;
        }

    })

})