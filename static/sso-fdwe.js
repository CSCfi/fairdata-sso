
function fdSSORegisterClickAction(e) {
    e = e || window.event;
    var target = e.target || e.srcElement;
    var div = target.closest("div");
    if (div) var scope = div.getAttribute("data-scope");
    if (scope) fdweRecordEvent(e, scope);
}

function fdSSORegisterClickActions() {
    var elements = document.getElementsByName("fdsso-click-action");
    if (elements) {
        elements.forEach(function(element) {
            element.addEventListener('click', fdSSORegisterClickAction);
        });
    }
}

(function () {
    if (document.readyState != 'loading') fdSSORegisterClickActions();
    else document.addEventListener('DOMContentLoaded', fdSSORegisterClickActions);
})();
