let darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
handleDarkmode(darkModeMediaQuery);
function handleDarkmode(e) {
    let darkModeOn = e.matches;
    let favicons = document.querySelectorAll('link[rel="icon"]'); // select all favicon link elements
    if (favicons.length === 0) {
        return;
    }

    favicons.forEach(favicon => {
        var sizes = favicon.getAttribute('sizes');
        var baseName;
        
        // depending on the size, set the appropriate favicon name 
        if (sizes === '32x32') {
            baseName = 'favicon-32x32';
        } else if (sizes === '16x16') {
            baseName = 'favicon-16x16';
        } else {
            return;
        }

        if (darkModeOn) {
            // dark mode
            favicon.href = '/' + baseName + '-dark.png'; 
        } else {
            // light mode
            favicon.href = '/' + baseName + '.png'; 
        }
    });
}
darkModeMediaQuery.addEventListener('change', handleDarkmode);