//Sources:
//https://stackoverflow.com/questions/14327151/highlight-search-values-from-url
//https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
//https://stackoverflow.com/questions/56387161/flask-search-bar-using-postgres


//Highlights search word in each post title on the dashboard
//Used as demonstration for DOM based XSS (?q=)

const search = (new URLSearchParams(window.location.search).get("q") || "").trim();

if (search){
    document.querySelectorAll(".post-row a").forEach(function (link){
        const title = link.textContent;
        const start = title.toLowerCase().indexOf(search.toLowerCase());

        if (start === -1){
            return;
        }

        const mark = document.createElement("mark");
        mark.textContent = title.slice(start, start+search.length);
        link.textContent = title.slice(0, start);
        link.append(mark, title.slice(start + search.length));
    });
}
