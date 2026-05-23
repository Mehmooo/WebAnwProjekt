


function addToCart(amount, variant, unitPrice, productTitle, imgSrc) {
    const existingCart = sessionStorage.getItem('cart');

    if (!existingCart) {
        sessionStorage.setItem('cart', JSON.stringify([]));
    }

    let parseSession = JSON.parse(existingCart);
    for (let i = 0; i<parseSession.length; i++) {
        if ((parseSession[i].variant == variant) && (parseSession[i].title == productTitle)) {
            let intNum = parseInt(parseSession[i].amount);
            let newAmount = intNum + parseInt(amount);
            parseSession[i].amount = newAmount;
            sessionStorage.setItem('cart', JSON.stringify(parseSession))
            window.location.href = "/cart.html";
            return;

        } 
    }

    const cart = JSON.parse(sessionStorage.getItem('cart'));
    const params = new URLSearchParams(window.location.search);
    const id = params.get('id');
    cart.push({productId: id, amount: amount, variant: variant, unitPrice: unitPrice, title: productTitle, imgSrc: imgSrc});
    sessionStorage.setItem('cart', JSON.stringify(cart));
    console.log("VOR DEM WEITERLEITEN:");
    window.location.href = "/cart.html";

}