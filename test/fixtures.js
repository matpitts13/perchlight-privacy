/** The acceptance fixture (docs/SDD.md, "Acceptance criteria"). */
export const ACCEPTANCE_HTML = `<!DOCTYPE html><html><head>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter&display=swap">
<script src="https://connect.facebook.net/en_US/fbevents.js" async></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-ABC123');</script>
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s);j.async=true;j.src='https://www.googletagmanager.com/gtm.js?id='+i;f.parentNode.insertBefore(j,f);})(window,document,'script','dataLayer','GTM-XXXX');</script>
</head><body>
<img src="http://example.com/logo.png" alt="logo">
<form action="http://example.com/subscribe" method="post"><input name="email"></form>
<p>Write to jane.doe@example.com for help.</p>
<footer><a href="/privacy">Privacy policy</a></footer>
</body></html>`;
