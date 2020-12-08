
function fdSSOGetDomainName() {
    hostname = window.location.hostname;
    domain = hostname.substring(hostname.indexOf(".") + 1);
    return domain
}

function fdSSOGetPrefixedCookieName(name) {
    domain = fdSSOGetDomainName();
    domain = domain.replace(/[^a-zA-Z0-9]/g, "_")
    return domain + "_" + name
}

function fdSSOGetCookie(name) {
    name = fdSSOGetPrefixedCookieName(name)
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}

function fdSSOSetCookie(name, value) {
    name = fdSSOGetPrefixedCookieName(name);
    var expiryDate = new Date();
    expiryDate.setTime(expiryDate.getTime() + (7*24*60*60*1000));
    var expires = "; expires=" + expiryDate.toUTCString();
    document.cookie = name + "=" + (value || "")  + expires + "; path=/" + "; domain=." + fdSSOGetDomainName();
}

function fdSSOIsNotificationDismissed() {
    return Boolean(fdSSOGetCookie('fd_sso_notification_shown'));
}

function fdSSODismissNotification() {
    document.getElementById("notificationBanner").remove();
    fdSSOSetCookie("fd_sso_notification_shown", true)
}

function fdSSOGetNotificationContent(lang) {
    if(lang === "fi") return 'Fairdata-palvelut käyttävät evästeitä turvallisuuden ja laadun varmistamiseksi.<br><a href="https://www.fairdata.fi/sopimukset/" target="_blank">Katso Fairdatan tietosuojakäytäntö</a>'
    else if (lang === "sv") return 'Fairdata-tjänsterna använder cookies för att säkerställa säkerhet och kvalitet.<br><a href="https://www.fairdata.fi/en/contracts-and-privacy/" target="_blank">Se Fairdata sekretesspolicy (på engelska)</a>'
    return 'The Fairdata services use cookies to ensure security and quality.<br><a href="https://www.fairdata.fi/en/contracts-and-privacy/" target="_blank">View the Fairdata Privacy Policy</a>'
}

function fdSSOGetUserLanguage() {
    var lang = fdSSOGetCookie('fd_language');
    if (lang) {
        return lang.toLocaleLowerCase();
    }
    lang = navigator.language || navigator.userLanguage;
    if (lang) {
        lang = lang.substr(0, 2).toLocaleLowerCase();
        if (lang == 'fi' || lang == 'sv') {
            return lang;
        }
    }
    return 'en'
}

function fdSSODocumentReady() {
    if(fdSSOIsNotificationDismissed()) return

    var lang = fdSSOGetUserLanguage()
    var banner = document.createElement("div")
    banner.setAttribute("class", "notification-banner")
    banner.setAttribute("id", "notificationBanner")
    banner.innerHTML = '<div class="text-content">' + fdSSOGetNotificationContent(lang) + '</div><div class="actions" id="actionsContainer">' +
        '<svg id="closeDefault" data-name="Component 3 – 4" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20" viewBox="0 0 28 28"> <defs></defs> <g id="Ellipse_1" data-name="Ellipse 1" class="notification-cls-1"> <circle class="notification-cls-2" cx="14" cy="14" r="14"/> <circle class="notification-cls-3" cx="14" cy="14" r="13.5"/> </g> <image id="cancel" width="12" height="12" transform="translate(8 8)" xlink:href="data:image/png;base64,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"/> </svg>' +
        '<svg id="closeHover" data-name="Component 3 – 4" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="20" height="20" viewBox="0 0 28 28"> <defs></defs> <circle id="Ellipse_1" data-name="Ellipse 1" class="notification-cls-1-1" cx="14" cy="14" r="14"/> <image id="cancel_2.02.07_PM" data-name="cancel 2.02.07 PM" width="12" height="12" transform="translate(8 8)" xlink:href="data:image/png;base64,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"/> </svg>' +
        '</div>';
    document.body.appendChild(banner)

    var actions = document.getElementById("actionsContainer");
    var closeDefault = document.getElementById("closeDefault");
    var closeHover = document.getElementById("closeHover");

    actions.addEventListener("click", fdSSODismissNotification)
    actions.addEventListener("mouseover", function() {
        closeDefault.style.opacity = 0;
        closeHover.style.opacity = 1;
    });
    actions.addEventListener("mouseout", function() {
        closeDefault.style.opacity = 1;
        closeHover.style.opacity = 0;
    })

}


(function () {
    if (document.readyState != 'loading') fdSSODocumentReady();
    else document.addEventListener('DOMContentLoaded', fdSSODocumentReady);
})();