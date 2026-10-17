document.addEventListener("DOMContentLoaded", function () {

    console.log("Mini SOC SIEM loaded.");

    /*
     * Flash message auto hide
     */

    const flashes = document.querySelectorAll(".flash");

    flashes.forEach(function (flash) {

        setTimeout(function () {

            flash.style.opacity = "0";

            flash.style.transform = "translateY(-5px)";

            setTimeout(function () {

                flash.remove();

            }, 300);

        }, 5000);

    });


    /*
     * Table row hover logging
     */

    const rows = document.querySelectorAll(
        ".data-table tbody tr"
    );

    rows.forEach(function (row) {

        row.addEventListener(
            "mouseenter",
            function () {

                row.classList.add(
                    "row-active"
                );

            }
        );

        row.addEventListener(
            "mouseleave",
            function () {

                row.classList.remove(
                    "row-active"
                );

            }
        );

    });


    /*
     * Button feedback
     */

    const buttons = document.querySelectorAll(
        "button, .btn"
    );

    buttons.forEach(function (button) {

        button.addEventListener(
            "click",
            function () {

                button.classList.add(
                    "button-clicked"
                );

                setTimeout(function () {

                    button.classList.remove(
                        "button-clicked"
                    );

                }, 200);

            }
        );

    });

});