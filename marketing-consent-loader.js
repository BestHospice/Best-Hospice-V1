(() => {
  const GOOGLE_ADS_ID = 'AW-17909571702';
  const META_PIXEL_ID = '1447731666875537';
  let loaded = false;

  function loadGoogleAdsTag() {
    if (window.__bhhhGtagLoaded) return;
    window.__bhhhGtagLoaded = true;
    window.dataLayer = window.dataLayer || [];
    window.gtag = window.gtag || function(){ window.dataLayer.push(arguments); };

    const script = document.createElement('script');
    script.async = true;
    script.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(GOOGLE_ADS_ID)}`;
    document.head.appendChild(script);

    window.gtag('js', new Date());
    window.gtag('config', GOOGLE_ADS_ID);
  }

  function loadMetaPixel() {
    if (window.fbq) return;
    (function(f,b,e,v,n,t,s){
      if(f.fbq) return;
      n=f.fbq=function(){n.callMethod ? n.callMethod.apply(n,arguments) : n.queue.push(arguments)};
      if(!f._fbq) f._fbq=n;
      n.push=n;
      n.loaded=true;
      n.version='2.0';
      n.queue=[];
      t=b.createElement(e);
      t.async=true;
      t.src=v;
      s=b.getElementsByTagName(e)[0];
      s.parentNode.insertBefore(t,s);
    })(window, document, 'script', 'https://connect.facebook.net/en_US/fbevents.js');

    window.fbq('init', META_PIXEL_ID);
    window.fbq('track', 'PageView');
  }

  function loadMarketingTags() {
    if (loaded) return;
    loaded = true;
    loadGoogleAdsTag();
    loadMetaPixel();
  }

  if (localStorage.getItem('bhhh_cookie_consent_v1') === 'granted' || window.bhhhConsentGranted === true) {
    loadMarketingTags();
  }

  window.addEventListener('bhhh:consent', (e) => {
    if (e?.detail?.state === 'granted') {
      loadMarketingTags();
    }
  });
})();
