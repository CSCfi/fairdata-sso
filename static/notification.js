
function fdSSOGetDomainName() {
    hostname = window.location.hostname;
    domain = hostname.substring(hostname.indexOf(".") + 1);
    return domain;
}

function fdSSOGetPrefixedCookieName(name) {
    domain = fdSSOGetDomainName();
    domain = domain.replace(/[^a-zA-Z0-9]/g, "_");
    return domain + "_" + name;
}

function fdSSOGetCookie(name) {
    name = fdSSOGetPrefixedCookieName(name);
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
    document.cookie = name + "=" + (value || "")  + expires + "; path=/" + "; domain=." + fdSSOGetDomainName() + ";sameSite=Lax";
}

function fdSSOIsNotificationDismissed() {
    return Boolean(fdSSOGetCookie('fd_sso_notification_shown'));
}

function fdSSODismissNotification() {
    document.getElementById("notificationBanner").remove();
    fdSSOSetCookie("fd_sso_notification_shown", true);
}

function fdSSOGetUserLanguage() {

    // First check if explicit lang parameter is specified, and if so, use that
    var urlParams = new URLSearchParams(window.location.search);
    var lang = urlParams.get('language');

    // Else use browser language
    if (lang == "") {
        lang = navigator.language || navigator.userLanguage;
    }

    // Check for Finnish or Swedish language code
    if (lang) {
        lang = lang.substr(0, 2).toLocaleLowerCase();
        if (lang == 'fi' || lang == 'sv') {
            return lang;
        }
    }

    // Default to English if neither Finnish or Swedish defined
    return 'en';
}

function fdSSODocumentReady() {
    if (fdSSOIsNotificationDismissed()) return;

    var lang = fdSSOGetUserLanguage();
    var banner = document.createElement("div");
    banner.setAttribute("class", "notification-banner");
    banner.setAttribute("id", "notificationBanner");
    if (lang === "fi") {
        banner.innerHTML = '\
<div class="text-content">\
    <span class="heading">Tietosuoja & evästeet</span><br/><br/>\
    Yksityisyydensuojasi on meille tärkeää. Fairdata-palveluissa käytetään vain <b>välttämättömiä evästeitä</b> turvallisuuden ja laadun varmistamiseksi.<br/><br/>\
    <a href="https://digitalpreservation.fi/tietosuojaseloste">Fairdatan tietosuojakäytäntö</a><br/>\
    <a href="https://www.fairdata.fi/evasteiden-kaytto/">Fairdatan evästekäytäntö</a>\
</div>\
<div class="actions" id="actionsContainer">\
    <button id="closeButton">Sulje</button>\
</div>';
    }
    else if (lang === "sv") {
        banner.innerHTML = '\
<div class="text-content">\
    <span class="heading">Sekretess och cookies</span><br/><br/>\
    Vi värdesätter din integritet. Fairdata-tjänsterna använder endast <b>nödvändiga cookies</b> för att garantera tjänsternas säkerhet och kvalitet.<br/><br/>\
    <a href="https://digitalpreservation.fi/tietosuojaseloste">Fairdatas sekretesspolicy (på finska)</a><br/>\
    <a href="https://www.fairdata.fi/information-om-kakor/">Fairdatas cookiepolicy</a>\
</div>\
<div class="actions" id="actionsContainer">\
    <button id="closeButton">Stäng</button>\
</div>';
    }
    else {
        banner.innerHTML = '\
<div class="text-content">\
    <span class="heading">Privacy & Cookies</span><br/><br/>\
    We value your privacy. The Fairdata services use only <b>necessary cookies</b> to ensure security and quality.<br/><br/>\
    <a href="https://www.fairdata.fi/en/contracts-and-privacy/#privacy">Fairdata Privacy Policy</a><br/>\
    <a href="https://www.fairdata.fi/en/use-of-cookies/">Fairdata Cookie Policy</a>\
</div>\
<div class="actions" id="actionsContainer">\
    <button id="closeButton">Close</button>\
</div>';
    }
    document.body.appendChild(banner);

    var actions = document.getElementById("actionsContainer");
    actions.addEventListener("click", fdSSODismissNotification);
}

(function () {
    if (document.readyState != 'loading') fdSSODocumentReady();
    else document.addEventListener('DOMContentLoaded', fdSSODocumentReady);
})();
