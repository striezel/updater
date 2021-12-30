/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.4.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "8569c8812f0cd1d13922021a84648bcee99762eb7ce2d7b6503692462bf7c9c66045a19fd2e3fd15951a4039f4611e1820a5237cc098e5b5a53796e1a4f5952c" },
                { "af", "3fa97acb4e0f82c4a656e90f9b468715590e3089425cb87dd8ae5918890a12bd3803b069cc74bffa7aa7631aec18ba53e64c6d07f4a6d70d97a111510c283c03" },
                { "an", "6e6c77ffd89fabc5a8c7c6491dc43413c416fb15177ca9aaca8013514f161dfc331a391a4dcbbe12cc9c89154e480131940a86e788db07b6738facc6c469a715" },
                { "ar", "0913e230594c148d609b19030b7b4965417f025828f4bde7530a0dfddb96ac5a6b401d082535e08b569b3c35e3ce6ef8206181fc56c5556b17c9f7efc3584154" },
                { "ast", "9f6b5e5bb2b63ecafe0b706680a6cd66933820712827b10f3d2370d10b4374ff14790dc092d2165671dd2daf40e9f56e27b3e385475afde43e4b7ea0132f3198" },
                { "az", "1720526175cfcf07757b9a244eabacc63124879ddff502f93f00155bf4c25caf73de84da6fffa2f5526288e1b5774c74d41b4491f39d6098d7020a705f59206f" },
                { "be", "db9a6a60e35478412786e1e7597f71b3a9923f1f554c824540d324e0cca351a2bcb27a1e5f3c394752b7686c9ec7b263e85aaa3deab3affef733f39e6bac8a4b" },
                { "bg", "6e956f3ec7b9410294998133087150296495e4952e2063644ae7ce6442b73cf8f5456905df8071e4dc919d3705a52cc3972b4b0b82b55dc14858b9b43147caf0" },
                { "bn", "1146b75587c1cae9ec6c8070ce129e5dd94831dd772448a2232209083e08666f7c2c9265b1a35da36c94c61eabc658d3a5d0490cc52705355d8a299de334d24b" },
                { "br", "9b493be4c1685081e287ccf0d596ef22b8f88cb2fb8bc3315a0c0fe531cbbbf03f75f61fd43bbc0ef626d852dd373d49cbd59b07ee3b8695477d28bef2a47c8d" },
                { "bs", "89f6da4c81c0e9f63cc0bed1f962744d6f16faa46a6eba4ddd2c41ade0de48653c64294f4d327315e4c46e83de9cd0a83911837d1197e4a803d1719b9c12c64a" },
                { "ca", "3bf0f7c952c042794f7cca0d86f18fa23687fa8a5c9e5f5049cf9cab65030c7531055e34befe766bdd2ddb99f8e144e7721f7d34ee005499cd4b0304da512755" },
                { "cak", "a9139dbc9fe4fa1ee82459715fb6bac21df60a2410b21858e046773074c79446a433d9b4f69db984f45c44561a64712daa42bb33f5ffa3931ab7ad0c59bb1b9c" },
                { "cs", "4b5920689dfb2224f031ce5146215c7573e6f01df0fb35bc5fb253cdb55fa097d2e1aee80947adc5eb58e6481e780f123a9c21b39c6db063ab029559af8109b9" },
                { "cy", "dd4b3f46f17af727dc5c07a48ccb68304a1f01bc88657163876c6463923f18064f590a2da624b6c5ede13e81b879b53379d5a76d0abf139dc1ea6963f1999707" },
                { "da", "bd65a528901cbbd7f48e5aa6314b2df8e8bac769847305803b2ed424e9cef93149f706aed8300c3b279d7c8bfe1a3a611f31d4e99f7ad2dff9f4f3183e6b6a8d" },
                { "de", "c422d9866dbf9a14f38927f9839455dd556b77205e47bed94735034890c43d0483dd5174d0ad1aeeb9672957544441589927eb08370f1348c8193de04beb7d4a" },
                { "dsb", "7bec432b8376e2655c3fc4b5638637ba2414c42db303efa2721c6b7e0e82bbc5855cb3797995b079933fcb4d0184fa7a9170570335207b0c22842c7e34a3abe6" },
                { "el", "f87d7a31ff8edf8641ec01bdb7f680df371e3d40346666cd82d6084a729e590118c006997d8952e4ff19687fbcd91bcd3e58b25d6685c4356c9f18f5d1a3a8b1" },
                { "en-CA", "cf951875dd87f0173ae495a014b7259e92b4c759c4afe2e96e500a11071cafa915df4ba6a4bc2cf01e10bd9c29ddee04c06f0c42802dc4582a5e0c4734dbb728" },
                { "en-GB", "6a5080bc4f71d963ebaa570b4715207863aafbb6dea027dba0e50b0efe335aa0cc6d64ce43be521699ee1a0cad2dd885b258c5cd53788cc2844e2f4179532b7f" },
                { "en-US", "1cd7f6088dd783c43a19bcdb24c2b7ecab6e30c3047eb77d291eb8781df16b1a6924040242bebd9063272643c41e9dbf177f0c2af117f61159212203200bf958" },
                { "eo", "50b173d4f3a12ae2f3383cac01e684b1ffa3158a3ba0549dc8a69468ea20166f3de071edfca938240dc294df5e5f5063d63d60534b35c379c08004e692cb2779" },
                { "es-AR", "1d18a9e9d31cb47506e7474f29fec889b1c26e6bbe87f9a5920b6aa5ad23a4571106decfc178167f14184975236aa6f735a26552ef2ed8830332c5e83726ef19" },
                { "es-CL", "968da3efa32ad904639f7da6889d7581af852bb1ac287d45846b4b3ea1f717bda591dcc0d03583de64ea84f79049b751d4bc400169174eeb66a8de7dfad81907" },
                { "es-ES", "61be5c5b9e2edd6f5e8d1d6e98964298c8dfc084d06d90f27fb322461d7597f87b1f3034b97b588348d04e77f00dad6a57d37635ce43406fa300f3ca51abfccd" },
                { "es-MX", "12e96f5cab623a1ebe9db3a57d32f0f03cc4342de62e4114bd133fdc1e71afcd900e2f8bd3ea3a452bbc8439d98a4f4ea3c712f786f4ff1e9c5e1de827cb757e" },
                { "et", "a231a1d6bec95cb759e3243cfe09644f159b4b477a6bea2c4a2b0880c693cc3b76b5ddcdd7da4654cac1f4b9725ae915945239319fcfda9b0fc8e7f989594e10" },
                { "eu", "564220558a0d1189f4d356574c115ca14063d1cc7af7d3b16262a1820e4d92ee3a99240d32098ad89877f74ca3ed63350c162bc4d6deb1fa2664cf6493db1383" },
                { "fa", "a3c7b3430fc2eb56dac4c53e0af021916357114b687b59528319148c9dc58349ec562e3131c67c9a771d1e986eb29bd5ddd961499d0d737b05a78a73e466b87a" },
                { "ff", "941405f76fd78f0be5a595a7fd47855ae3382034c5005e51ed38a1c331b0a2ab36cc9a28d5408b2e2503fb6e3d67253413a6b0326437b88ad86852d542ecb5fa" },
                { "fi", "1524bd296180bd87a908cddd6ecc91163c2f60252740a089e7e5014cd6eee25e6798db721d605d7aedcbe8488e66ad22ad3c97d6e35492494a72dbc2fed0210e" },
                { "fr", "ef2b26170be3db15a194b88db79ca53b63df21c7eb75b3af65d630790bd081ecfa486a41bdd10bba169028882b367ed661930b63f3c70d60f0424bf35443d2ec" },
                { "fy-NL", "49787a83ffa1be803a04a74f541aacf9feecc74d5f885b2bdf6ce4deaef273baea6895a289cf32a5cfa5006c4b283c1578805d779bc152f4ea1f459c9698728f" },
                { "ga-IE", "ba2a3dedf1d0691ad926c34525f2189f14f164aa62cfb52d2b8a61507ef9632c67ac4a7b4cd377d07cc8242ca5de9b9e3a6ebf50a8186308ced565ed9325aa05" },
                { "gd", "7886a54f3bc4455c5a1f7ef76a9a54e12b81e54071b5a2e47b171bbc83b7a0c09cc495331e41ac8e3082a45c3db305e882ecd622d407cd8f6d90fdca98f99532" },
                { "gl", "832e57ca297d71fa1fe4f52eca1f6e5ddfdfd5f12a136d8d79b272b50ebbaf9b2ad153277e0960f80ea73b3e0e4a2dbf4013e5a86ecfa52b7785a60fc57d3b69" },
                { "gn", "81ac7266d6e449537eccdb2bb430d65ac7c89670d6771139b16de6d9a0cbbc9c223a4f1f9e3c9a385a980e3b52e4605de9b2b32fa2453595c6abc250dc62ecef" },
                { "gu-IN", "6f4b285194333a93f515a2cefb46818db470870891803a322902f7fbfa3e0a1b8c70bec2a3b1cef7b760235f02c3aeb6f7b54445e976ed775c2a4ca7904d6a9d" },
                { "he", "131a6a033cb79538dfa30653657c44d4ad1ff9c4dd2fb0ce73e0f63b84ed986ab5a1ccdad4cb9bdb611a9c5e36d30c732155e6a31df7bb106d036f27f52440a7" },
                { "hi-IN", "af7366a9bf3191ba40efd693fe8f2f5e293ade3c0c982948033e1046028ddf05a3e32b0c4b780c2cbc5ded9e61056d07e180db6ced3a2fa7996db01f023896e5" },
                { "hr", "dabf363e4f4ccaeb0dc045c850dd1de5327ea50f921cb438bee3b7b37f3b86d4d3895b3ee2ed63d061688316ad45fb2f551ebd39597f26bcedc6c0a58fc3e267" },
                { "hsb", "45dd30fa3e02a6b314f73f405bc23b4f05d0883d6a4643052318fa461b03379b9ca07baf27e687de3c05efc4a6aec9a6b4ba4cac2d5871775e6f2c6c98a311f6" },
                { "hu", "cc35bc96355b0bf75fc481f40ee8d56e8b1b244113d3e45f5009742f821d15fd015865eed6eeacb51b55766e4ef5a91c7530ed6cad6f6c191fa9fc776c33191b" },
                { "hy-AM", "57265f76a64c331287ac0a8624ea3961e1610c0cdb6969b36ef66ffcd69868d7b37cfca42e99334cec6b269bb263802c40c127a5ae80131aff518bc501d94500" },
                { "ia", "2ffa5ddff84d4815ccfa927658486355d837a080f9e7ceba85ac720bea53577e170e5f65512dc20ee845654755c14f1d5cb087f42862072d506143ab6504e0e0" },
                { "id", "a0d7b7924877b7922cdde5d326bf82117a1e246f6ba8ed0a39856b660088a164c08e7e81e1456e00340eff7ae882de36f41f69a1b86e71a194c9311990a3bc30" },
                { "is", "29b9991b8650e3435493e9bd624255bc9616407fee84e76fdb684d41c6fc69f70891a2d18e5697cdc29d9468e7256b49216a864c0d41345ad27b09709b6524dc" },
                { "it", "d3f3b0caf822030fb3742ce4bae76e76da8509035dd40596af3f358c1fe82136f3f1a711bbe1ef5dba682a658c9e99618a42066448bb25b411b83ef34f9a6e3f" },
                { "ja", "5af21a16b650b1a6210117b2e449c895d68e141ca3fb140d22a5f715aa47fc6fffb6e32eeb2bfce9d1f37d490f137e6975b0adab8e63fd1e0254ebaa7b200b45" },
                { "ka", "0ca2f87cb54cf6b2bea92a805d4024065f9fcc045d1e62bc4aa4b0e676c41592af7fde285b4ce2b3ede1e1b0e97157290d59506b8db9c54f0bc62b47a3a1943e" },
                { "kab", "c94ef3816ee4ceeaaaf1b408b2cd57573f3d88315369078ea7479903ae17258f9abb1a5ef48967e7a2f6bcebae87650fb659e875f01ea7f36fc14b9dee748ede" },
                { "kk", "ffbc5f45165a9cdc1ea16eb09c9249de34ae76ae192198918dbd816ee8854ab046304588fddeb0ac797e208752a47dafcb1803bdb07541988f54610180e07129" },
                { "km", "9c50dffec6d3b3c821e9f24cf0043b90380be9dda5d3e61442ef57714acaaf1b6c0ef1188137436ea70b1a5183a2c06683aef71d034327b0ec227012bb6db12f" },
                { "kn", "5abb5b59e57fd6b795f4a66bfdb80d241a848c7aa5917cb82c08611ade0477a7c36834dad6548194e819351d8359e85ae61ed63dc7be47a9b2aa5bef93526c02" },
                { "ko", "f0c08d13086a27dccffa1682d42bf7cf6fc7ea22a233997a7170c2a294637931a0ef3370da6dfc0b5f49a888582fd700edd5d38d08fd0548213756654b243fc8" },
                { "lij", "ac97051b102e99b4e38eed9a7fba82f9b80b7da18f958c17c4767343c91d6bceb25e7f4fc567fe0fcf63a3c2706eb4e8ba0d4707e3446ff1c5f6825f36c9e216" },
                { "lt", "a204550f1b807c1d5f5473a5a045694a5a02622bf694c3dc0c89c6a12c6ae88095734e861cfa7772765e410aad62e7792e21fa091e266c95e30bf7f70ce3d342" },
                { "lv", "d7028ba2725b1e633575c6894e8685ddfbd28d121bf9bdbe22d3f2abde228aaa9661b806c71cd47fdb418611d2837db99970f2568153b994acaf66978788cc5c" },
                { "mk", "955a673dc3a45035813d999c96e523806a2f9227a6badced4bc331c5ebeb44e3d5567594de05d8d4ee985907446c1188dc142c00b1a9b94de1cef0fb181bde2c" },
                { "mr", "832d9a189850b632f7b23ffeaaeb3ac3ea4767813003f25186c92710f8e4a00f8051b9f446edad3303dc88019474810c62e76aba521606003720ff9c3ab931c2" },
                { "ms", "4300c58d94a767c39d321d7f814a636c9d7367a8f929937b5a21d0373abf6813e12eb2fc2de2f538cc8b5317d19c6e5a3d38c533a0eb788d336747985b8c1eb1" },
                { "my", "f2520715adf3c619c41d89de3e5271dd7912ed7326e7586d75012712ab9051fb9f262d2daef2cf891cf36a13a3139068e305b100dff98b6d508e6eda804d3640" },
                { "nb-NO", "19de157d193273d494d8511aef6403d0d62a406cbbabc468e0726dd2f74299799994d5d371c29fffb5137a6c11d8b5ed9dd84e7b96acf4a35a28ce4b53720ec2" },
                { "ne-NP", "f63ddbea471ab6e3113086b6bb8444f7158a613cbbc34a8deef2c96d2a90cadf273379bbcee3a2caa904d316e8f32368859221fd1e617d3366d7de558e39d6b5" },
                { "nl", "a36cb5d912f9f68576863a46d51d0af2c2d83a89584897f7b7d503ff253179d7ea65576495897291802cdea4b5bea89d5a38900448fddd714b4103ca21d80662" },
                { "nn-NO", "2c8d739ef62971a37281fc043990f53019f00a5cd59049e2f7ab11d3bce3e75e7a136523ca48aa2c5338f850a1525d41b5c7a8ad911e3b21ee49005a3f358f5e" },
                { "oc", "728e39881bc7e442aaf5e6e7c5785132abe3baeaa2ceb0219c0d88ab83bf23e8b882c44351e0c333bcc9cb185ce469db2d13aceee99239721c14975d8f7d435f" },
                { "pa-IN", "7cb7c114695fc47471b89ed5fc1b13b17cbeb49126842b84ee1926e3e8818ecd7dfc024f3d47c0ab2d6e2bde9d28d911428829bf39fcb8e88a1c907fd846ee08" },
                { "pl", "e231c67c2b0c4e11ce19779f6b61d152eb09316a6dce6c9614f97b21e1d0cef57e65667721fa20f4991def3d46848929b0ef3d47c3716f8e7c0a5037350d37a3" },
                { "pt-BR", "6c07053f7d23de0de0eba3a623661d704bffb5567d342bc9af7748b8d5535920e1e8797b1b470b790751fca9a9bd3ee1a281d1a8f49af1ef3acb3c59227a6079" },
                { "pt-PT", "5df5537750bacc8e33918e29f7723fb40645f95aa79614258de1ffb4e39617ffa80f483c4153f05b7c484ebe4717fd2413cc34fb25950957d66df7c286e1b664" },
                { "rm", "f313b4bffc98c3aa6258ce7250f3f4d2777890ea98e9f4b6bae966af2a783b9f984ad9f13a72be9a0488c67f2a9c78dbbc755dde439887941ab6978276daa8dd" },
                { "ro", "0afa4ce8db6324c472b4d0e693f7002ea4860becd36365da0689179d0eb3b745d99f416501841a086c44ccd5ccfa7d351af73644b5c4ad62410e4242b4010f6a" },
                { "ru", "a4d385c572736b5a3c0ba32f69019cb071e011438b6ec0ed7cef452fddf15cc1f1bb52df2bb28256ba43e7beab71f16354147cbc3108039851c4982fdd6e8565" },
                { "sco", "f1c250a7d7fa524aab4de4ace4eaa5c42a6472441a985e4cddf9ccffb740b7110559348370f0535b7fb76d295db3db40143b6f58537a47373432606110d354e4" },
                { "si", "48c1495d3411d09b205a4d38c6c4b0176f17182167f26e8112c3b0e0233d382f3146956bafc380003643f95f413bf4e1be9146020af3a009eb582c6b43a44e92" },
                { "sk", "9266fd7a6740ae99292183592ce7a7595e26c0de56ee50f479b1d094031cf5a4981a8bb8673638bcfb6fc89942587280a44231c43da54611767cb3220d96a0d8" },
                { "sl", "49cbd5c8f53ae39e6d469001dd3bf01d8fa997dd84030a0e84d34be7ccb4150e9b71fd48fadb051cf508dcf32dceeb72afc224a06422b18653d014858a16ac68" },
                { "son", "f62f872d151ac263f0d984c69ecb1d25bbd20509614462c14954f768239d90112b03b083e6314e03cc9b995360785b6054b7493559cf85ce7e0d81e5dc694941" },
                { "sq", "ad674e26c636c0da39a284a81a152e67ca02dcd31ebd0e4377af773ac9481452b3a26dab77d60a5311e40f47811eafb0b4084f068d9af2096b81a76cfee56ce5" },
                { "sr", "09dea2c2a1460294bfa1991789994623367ece0388a3751ba742791ffc96244983935a9f4ff6732d2a1090cbbf65afb938ea75b8d78dd7efe3468df57a481ffb" },
                { "sv-SE", "7122f7d69376afdd4147ac53bfa6d11e7ae95b7321c60c05accadd22eb4636284cc793e554cd94c6c9ebccff1bfae9630f14b67dd3071207bb993ee13729b07b" },
                { "szl", "d0a2672ee757c33c06d1ef7a82a1e28dda25b019bf1664394680a6a3f6a7322a4a2573720129a0c16ba071355d0b335a874630ff2f675b2bb63c38f0541c03f7" },
                { "ta", "f0962beed14859b6f969ba6897f2855236e092db34bd3d2182fba7fab79a7e51cc843be128b1a0a79c6fea908b5bc7fa7d62ece328812244a1fcb3fead627efb" },
                { "te", "5391693f1e6543f4b8fc5a32a343d6042689ee131cca4560ceb10895ec13aa8bf6543b750dd84458080820fdacf64eef854e0c498ad01b80b5854cc8a9d0fa1d" },
                { "th", "03615138f3b704dc15cdb6ec17c8b362f97929533cf0022eefa8055eba3a4d45de2b8b80982f5c69b7fd512fab4c6edf9872bf6f94b24bf793323e2ae18589f8" },
                { "tl", "75b42b173ceec637a16c3094fa8feee03b51e18ada0aa5a3a4a39a91bbb410268218ea4bdd02ce29b2ab052e96ad84870ebf9f1e3bf6bc602a383ad1c95af427" },
                { "tr", "07efba8d575ae239603d2bd686bb8c4f0004da0c426236e37dd4497b6e7728c023970b1e647e96cc9516b8b2878ba08c494dfd09f0689c02b507b28b916042d9" },
                { "trs", "4340b24ca3f490da32a40698612ef99d25fce4e573be0028de8bffbac0316280a28fb3ed12d0ee5ea64b7755baa7c23226865bbbe8026af31b5e7c3cd922e909" },
                { "uk", "af535ad3b882991c8e802b754c717ab7cf4e892b514af87dd667a9627f352c2aed482c6d54247639d56dc4c3d80ea879884b6f108a98a514321fe933b3846345" },
                { "ur", "7fec3fcc8434a5db1e02588365471a54bb27dbf5d0d07532f3782a87cc7c3c2b0f994bd021957d76355acd23c29c84752d818de5b2796d760295641572c463b4" },
                { "uz", "3efaacb6b059ed2cf81928bedfd005113136ad7ffc83549c72046145ff16cb5547ac46fcff6dc08943c6593486e3078c3d023630cfa2d0ce66dd55c3bc29da8f" },
                { "vi", "ec60f0eec5b85fd6081e3eb4c152428cb63b10efc4f060e263a4b14d05f478946a7770f988fad646e1997544c878a2072a312283ae9c46544a861f57294b44ff" },
                { "xh", "e5ebc4c1fb5607d3c3b897b200ad6000c94616f414d6373ac704e6b31a8094cb376219cdd6f943e3d89a1fca5a851fe37e8a39e5fb25d50aa469d18afd76b8fe" },
                { "zh-CN", "c9aabf49351a5e1be6be2154ae217c115b755c5eb300470eb8a7d4fee6dd47cbb30cd80b6334e99d098447522a247ae734e36e5484e3d50c02c100bcbcc843b3" },
                { "zh-TW", "32dc0cbd09b5fc5ea33235eabc975d38aa174c3731fe7ea13ececaafa7c7ddcc7a938772623d771a452f60975caab914fa1f85b24d83c9244da45cf42d647690" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.4.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "9b577db5f9842c212aec48397f0db09b35fa4b759e118abbddbe57f5ae6d2b77cc0f809f2ecf125c385b3283473bf1a09f5e2ae8fbe75816ba42aae2f84a352a" },
                { "af", "3d9a2dc7aa666e0ccb90975d079a51ac6e39c0e3636f5aa229f976c1f13f55b050c4d8c3f0aa8fc119fabd6b5bdedfdc407dfaaf03ea799a102abcd1ac2d9827" },
                { "an", "f2c638fbc2b61b4cd2c05f5955d0545ffa6c020bcb53c3e49a9b416f1acc24efb372869a06df91a4ab20434083596309bb729d56a0c6ab3ff29e477eac79737e" },
                { "ar", "abc27e2e67b7384d75b1c0619a40e89a6f91cb37588bd57d8ce8435c5d4f12e24d7d2c7c446a41eac14164dfda9bf9164fe6742c5176a56d769ea803fb8abfec" },
                { "ast", "7cd2ed8ef94b2885234e687e2711379e5b925a2728155b7c7f1090d0f2a659b0c4d729edf22208a43472ed637e15af663d5b810c5aebca3e45537ef3c713deaf" },
                { "az", "36b7501f1511d7284e4565251a04d7d5eddbad362b045d73d5d28457f4d22079ae8efb4304fb76cdc5f6e0a732ae25b9a2a3b050ee5682f4ca973145577e8171" },
                { "be", "b19ec78124020b7c3f3fc83287b22875cd674985ac9958f62ca7562ff698dcbca8b15bb2e1c98c1d65727761eb1a622b0cbedbf52cb9f02e047647ab0f1a834a" },
                { "bg", "0cb60fe924554b782080e1e951849cde1babb6faf28418067b49e34e30e529c22a58bbdb4ef74e3def513ed76bc338cb9c1d0039337d20da85ed566fc0fc5dbf" },
                { "bn", "5aee1af6301d39bdf952cce2641b71beba374278b439e9ec9a99099d89150f3422a78972e3e82566242e3543751276df0acfbe7be5cb136d8a700e7f7481a120" },
                { "br", "ae1e5c46cf4228d26b51849335645a5790ea984b5d5a7724c99b1d25727f986d920ae85d0843ee3c9d9d36c107e879466a84d1fe009ee94a0918e31b451b56cd" },
                { "bs", "7a717ecae7b1a196ad9969aa901ab207ded342c9ee4b54774f2d1e1c7887e72e814e54aef84983d92b2c0a2c6d2123e89a7d2fe5d1cfde251626fa8a73912c9d" },
                { "ca", "193189627d5fc2e6c74f1c2263e17e856c9df5cf6eab72f3f428f0e9caee839bd4eefdb450d38e3007d4fb2a0adce38ac4311eeddda699a64cb3487736eda892" },
                { "cak", "b40daf5f3aea40d83cbcbad9e3f2642df748ece15ab13198ffc999bef13b793fec672f03203c1b3bfa318e729509972d5e0c56d9dd9beefae7b78958a7d6db30" },
                { "cs", "2855128d23ac62115a137220519caa464361bd90c91109a9c6ea0b289c6a64c1fddcee9a5a683e6c75cbc652719b38289dec63b8f82c534bb94b129b087458d8" },
                { "cy", "a3fdd81a9f5e8c2c7a67e9d589cad1f383f69d31d769d322735afa8e5e8b97b8caa8e9cc96db5f1f457e2c44ed80fc3749dcf37e305282c020732a46abab2c3a" },
                { "da", "a154b95729a0cbe3cb10703ccbc55414d32951ff09579703654363fb66c3fc5ed09345166020d1bdfa19c0a4dcae6dfbe67ccc32d99520854ec04cb1e05c3a3a" },
                { "de", "a02f1caa48f7999bcc76a692fda259aeaf636f33e902bee8c066944e0c21ffca9e7719f8002cf5a87eb451914d93bb2f54d411336b0e143c163e735aa82fbcf4" },
                { "dsb", "5f43443d5b558f30f539e4c556a0523bd87a450dd646736534df892060652c00494648a8bf926f21d10af8155ebb745179ef6a3853bbf20bec39098a2d444497" },
                { "el", "61bd6b9825bce3aadf8c87cb750a89c42a85700e92a276342e91113d6b55c9cddb3085669c93bae0b919966dc11be6ac7776af8ba408c52bee996dee7f9e3fae" },
                { "en-CA", "c597b2c56eac4b996382df557416975a2c39c25f4876805fc098d7a21e85860ddb2a651505ac057f17343fc5dadfd1807d2026f57665cbfe389557bfe33ccdde" },
                { "en-GB", "4e19111a864959349e9b47952243e00273610e010df647c464a3fe8d810b45c7e27bf0ee0d17f9b3585e31fa8096ff2b62a277b55927c59e1a6fbf73efb43d0c" },
                { "en-US", "9de833ae1c3895123160dbec5f36acc8c0d35e873333e2218a315cf8868026e17933fc1b9377cdf6fb91febc16e3e0909b833aa435697e90de3e556d93d25234" },
                { "eo", "54a4781c9c8258d25a4b843e9ae3e2f0e05491ed36e89cbcc69398d87e10f5b5f7224cbd91597914563fd07bbebf359465d43526f7e74a7ebba553ba7ae547f8" },
                { "es-AR", "7eca6abe255e71e4e8a1f3e516de691c623ad1b06ac374d5c24aa57434d1f068ac01c29c943d516ee82516cc44de83d923c84fbcf42e92f6e8159eaffc191157" },
                { "es-CL", "448fed38adcafa8d2979c8546d5c36dc2f3ab45642f3f5c428533bad2ebda3c94ce65cb77b4c41b91e764d0e3db2f874c993be62b412e86c5845dcfb044721dd" },
                { "es-ES", "722b046a1839b86b7b8cb81e47a91ac03a75420dbdf51ccadb6622776b645bcf860a1e955fe5d0186a130fd38354f3ebd7fad4d57bd04c5eb479a49da9890903" },
                { "es-MX", "0e615659b951ed26e657a1dc41859dc88aa705ba2ae73beda47dfe2069dcece2a9b5babd333ae7cac9507ca35cf9229f3dade2cb5fe35f6cc19fd1cb0fa62627" },
                { "et", "5fa7b9bbc281146f3ed582c08784af22a4262709300a3522e4b1f90939cd7e957188c58067c765170e8460d7d0344dcc8eaa4bfbdf95f8c19167c2687919e449" },
                { "eu", "bd1e6e9ccfe2a7e4528e20f33461a3e7600e67a2db4a3c75206871411d3a02d92a0cf68561b35ca1c24640688b5bd66169b44bf94cdd86dda747be58a21bc1c0" },
                { "fa", "2ff03fc4dd991f1b3e7c6c01b1977b9da077f2340218dce6660fc5ac37a1d60d1c2ce4f78a895f1e2219d52ecaebc2dcc336eda015a317b4ee3278ffb61d0cc8" },
                { "ff", "7ec5a9585dd01058d5fb626afdbd90211d5fbd9ae9770d0dd0ec7bb33cdea605b542f2e07512543eaa607a18687e5d72e692920ddf7755d5c8d59c176167ed3f" },
                { "fi", "1060dde9b2b5e7b432207cdf1e3d1c050b48dbfee2d8e9946eee17195d5aeb4e1f1bc256ea9a60452ec19a49aa7c8d1dbd35257fd9b7516ae429733a7fbc1826" },
                { "fr", "5bba4e80999bb45b68379c8d8e9d728b9396004f66ffb162d37b740d448c2c7ffc30931cb26fc5eb4448876b2cfcfa1a783d1f492296af2e7869f65d52862ae0" },
                { "fy-NL", "6481edda8fedfb15aae3128c804952c92d0619b3fcef901aa864b34aeb85ea6d9a460352b7c659326176e4de88b47c76181954d4dfe976b1ad44462737972a49" },
                { "ga-IE", "aac1deb20f127449b39dd2c5226ee79f8ddf8877f01f6a3d5add5b8c04fba423dd7c66ee887fb422f68e973f62388ab9e7c3d14d23e79e2ee74822726a6388dd" },
                { "gd", "a84dc28ab5d4b3aa2c8025b275a67f7d4064c6036fec03e55a5f52f5271c18f63c0c6b268f27f6cac048a7ef3346da1c98d1f961e04404127371a750a80ef275" },
                { "gl", "c68b22377824d7f2514b5ed79a44852c40951fffa62d79e709d48095c56d7e4c4a96cae9b8a08ee091a648d8c58b9da4be7175f5140ca3b8e1b3e2710d1613ae" },
                { "gn", "d92f2b5d8d3d1cbad285fa0235a41b6f44ec952bf7594e88c36a2da7d75327e78ff4295721ff23535b144c48e67a2ff50814227e85c04f02d559c6c0b80d7e85" },
                { "gu-IN", "d660be5189ccbe6080a1ae916fd9aeeb856866d234f415c86db4a641bfdfd7d8cf008eadb249d11df98455063d71b47151a56924057943bee2f15fb373f5d639" },
                { "he", "002c8cf5e74e5603e7a78a8c69c98c7a8ce7f011afdea16d731ae81db87569d01151c69aac2edbaa711c187b57914f115ad4ba16423b2d5296064d826999750f" },
                { "hi-IN", "4397e09d53f43118985f4851aa4d69884b969edafe0b7c2938ee24ff83ea28de41fc9e5ef80c73b1d0823611a0866f0cffd61883be92e8b09bb5a62362d5f3d3" },
                { "hr", "ac02567daf1ebf49dd8a8af4bd9aa51cccccfbf947038e11d9a2920a4bf131f7189e7abb5a91e34db8651a2ef97e0ab9d25f3872c1ab1a6f680df14093037df9" },
                { "hsb", "a13156ec0606b675cd78695041272202dafe92ea4e3af99d322213ce1910ec1ba278eb887b395c76c0516a342270a87c4f38a101d6f32b03f8f3c67c1b7919da" },
                { "hu", "72e4658e3b4a18e1b5912ac581921139276482972f3e7ea33167a0e0f4592470d41b6292cf1442ef58566e3ba95eebc75c27767ab67f899373ffa08a2e5ccb95" },
                { "hy-AM", "2a6a713393e61ab60d251b4f6e386b335ad5d3435e776cad95249278bdecdcda0c757910c681fd6c62139fa52ab61e721bac5f8e04e676446309ea2cf89af7f1" },
                { "ia", "01f0c5c83c6be6bf5a4c95c2348557c82caa38d4daee9fcc9e17f376687528f1c500d1de33bed042a4ce8f49e74f1cd484f8cfc92124baab1192187f5051f768" },
                { "id", "1ab3737d206d2400fa93c288a1a67eac6e391ddcf864705e5eb649cf63800c983b817de58875e4e73684a74a1f84c01fc3db09f60e680c452002eb5531925d5e" },
                { "is", "cc32036b5982a35120fe340f791591c5f987c78114f774c11ac4e7a0db406f9462a816a8c526fd95deea955da80674bbeedc63d8169b452570fce49bb21d697d" },
                { "it", "0a503bae33ac2e89083cd6869b44162489ad154542bb6636e2dca328d1dbacd81aa7b838199365b1cd4ae96ddd63c82c31d26324caa4d5dc846c88f349aa3490" },
                { "ja", "d9b0e3a0a7477ff5ed7db8593260ad07c1883c97ae0209d5b26c98b4fe3114030e8b6fc4e9f2d4d40b7cd1f22ac7bec13ea7c0825afdb3cb29d7876d69b49c84" },
                { "ka", "555cc2818564ab25788975c842d0329d8bed5531650eb6c46a6eba9f1f524cf178740fa72745014aa9d515a010776b2eafb4af25ecb183156deee3ea953b23ef" },
                { "kab", "6658dedc7e93dcb645ac797f6089fd238206ee9fc9109a6fd945e1b9cb6516ec0b040185ebb13755ee244ef35f95297cfd4b7e3f2ad654100fe0b31668322666" },
                { "kk", "62a531667957c21a009fb89b46d169752a07c4510c578f1c38a29cc9580947df76a7e295744040651027779ed8bab1c58ba35f3eded1d5e093e609061b32ffb6" },
                { "km", "5e7c9a835b85804c900355c364da9dc59d770038be6569a57aa145981847a114c9215e242062b279df3023f85a31fc055f92d5f585969a886e70c4e481e62261" },
                { "kn", "0ae52231fd723029a8f0b246c6042ffbff91d3f8182b72cdc5f84fbd2b2daba3fcc019159c17b5b2fa6c5499745b3fb667337c05f00a9cfd13ad2b2b0a45a6f6" },
                { "ko", "77f83f05e31dcd7d3d53305d12688ddf5315f98d199cb6cb1dcdd4170416ebaa9f0025fa342e0c2c7622638711217f21719753c5043836e56981a2c60fffa985" },
                { "lij", "6c7de38836f6915dfc88219063a1a34a8c5f5daf2d6945dc46f5ec889f42d9f7dad872f65405a07bb003d48455aa5cc4e3777162ae958f9311798227a9ad96ec" },
                { "lt", "082afb1f01b4fa92685a8463458a2fbf7ccd3d21c269efc74086aa8234baf306ceff7d18aa60fa5e20676349f06b8860ab1592e404b5f93aac396e6881d95da1" },
                { "lv", "05048bfe3d5d81191bbdab19515ff59a82755664d330c611bfb0bb991d8bb06be39a4830b6ecf508e0d70bbd2ed41bc5c620df292b02c3b4d4e89054a812b83e" },
                { "mk", "c5834789c7ba7e64c95418a18e4d165c377dbe29fa8a55c7269e95956579519817f73f16ce79fee9519d46ba04ff6a84c4eaa286518ea633040795a80af7d5a4" },
                { "mr", "fa73df434af3c3a94650909d01c4e6979dcba23cdcb243d6ed387676a26144678c09b678e4801d3ffc3dd708b624cd436fb7d3ae3ee95466aa9f8937e8cf48c1" },
                { "ms", "0f8ab547ea68201ee7c547c2ff5c29dd525c7da60594d817f6ca8f572f8a7afe4537a545ea3ee57b39452679f86077382e80c01b275265480a37296589ed8609" },
                { "my", "4c93a083213d674e5d6b81d4e3826c5f1c594ec0e956286ba1459f9a77c5fc6093045299694ffdcf84363ba3649166f2334ef98e7e54bc33fbd3954cce1a0ed5" },
                { "nb-NO", "c322a37ade3459546c7279238bdc20a1401f3c70cd8b2accdab5fbb7fa54f2066e486c284a174970f3afb0ac27c75b461eed5756b2d1e7b5a91448bed4ef7e52" },
                { "ne-NP", "9c26b8f149f2c4fc3c23d93c3be69248122e41adb8db87fc4285ede269f5a7dc7adb9d4f60296341f1431fb918b5630441b96c72ae262511beb8541a34ca2a15" },
                { "nl", "3434f87cf0e59b1253ca04c9abcb10105c5a187cde593efa4924acb8289ca93545609c805816b24a33df38a023b5aecd563e62d0e4756b933737f80d800d00d7" },
                { "nn-NO", "ea8eeeb38e1cbe1c945a2cfc0708f38a69d90af53de9bc0fa66d9f2ec4dfb99fede8d6688d552c4d94c36d2ee5f76c7a0e1244dd8bef0dcb93e8b4d8c8129fb0" },
                { "oc", "268a1bc5a71388436ad8c20518bbe0aa6d17d87cf6eaa5132599b41ec688af004f4a18c069b4288425efdfe26f1e8ec5b76ebe177858d553e656c84fbc040216" },
                { "pa-IN", "1739af78b02a3a033a161a78abfb2cfcad4ea6856c94128df441c9ee4c1c305c4e69c8b7a15da9580f7ab6cf8652fca3ebce8c7583a6fdd496ccf99ac1525d74" },
                { "pl", "5e3dd50ace9c219171aca664576d8122b525d80f26ee1db9a7c2d3af130079d0fdc45d33e4f730410dd9684e6d25c9af1af1e5ec5dad10bda67db2f52125525a" },
                { "pt-BR", "17e727b92cd44dd2b18753a77c1530c85857cc64c8d7541f7ac78d943766d70b29e315287edef66f9a126c20de75afc4730b6635714143cf89f72d26f8288f0d" },
                { "pt-PT", "f0be7336fe881e87ac41c99c1881a88a4e6e1e9f2cd28b441475e9b34c385c55753924bb3d0e056458a0fc16147c2b02c6b22d628125ca0c72c895eb82f8c61b" },
                { "rm", "afa7ec1f68534ed827f367becb14f8a185bef79d2733785803b1c61d16fede76ebc0556ec847aaeb711b6ef5ca4fa0b206765a4155a672faeb00fb0cce931336" },
                { "ro", "b808de866472af55ce0214e24c49b79094bc9fc440ec7751119d4e5acddfbf80a8752deb3ee73163c838769210914c90364b164c1972a5dcf5f1774e38bcd23d" },
                { "ru", "fe7b8503796d53d9430fa74aed1cfd7f8dd1760aede4299e292c8253fd3cdaf13ab8af9d9fc2ab63f5fe8ddf93fe0f7eb7cfb1e2837d7f4fc2c219fffeaec91e" },
                { "sco", "bc16b8d5a2dcf7b1d7aac65b941eae297e06bb3d1deab2ae6b0867bb19b14790d36022f0d99f6f15108f69dbb4a9f8fcb5dcbf642c761a41572d5ebbbb243955" },
                { "si", "f5bf7033922bb9b4dea955275a7084fcffd62cc6e3b5bb278ea31aa82c5eaa1f95880d4f40ed8ca0186beb9165c8434c0fbc0f32e8dc9857f63fc16c2887754f" },
                { "sk", "10b17eee7bb94f055f25f68088f672112bf194b4fc294f05d4ba0d8a785a4c00620bf29225d554219eac23626454c10938895af0e3197703994f2d42f334d1ff" },
                { "sl", "fd30f152ddecdcd13cae26b4ed33e790c99d9f1b39d19108c09da2091176ce3027787a451dd9c58cb0d619b4324b433d2b460258f583b5879065f8a34f0d3fe0" },
                { "son", "898d7469adc4b109dfd23ba7e1735234c1d06e850f2d4ecf324a026b4d377731dc0333efa4ae9830491fbec9d7695d279baea6e446253c91ce54514496bf43c6" },
                { "sq", "7a841e5ac79516a3db7482eca0399f7fd299cbd9f539968de7e177d64e670f5a72b70d842023739378bf7f0af4d76668699ebf48c9c155ab52614367a2e0bcf3" },
                { "sr", "b629e4c686bba203309de320e60fc49248e2301ddc5f12131ffe908fa94ba359fd6f6896390b39b56f36b3a3f0bc16c82f5b6d81aaf2e97c0f6fd31e630f4a03" },
                { "sv-SE", "ed79a8af44ac3a0d2b553b011f8f34a02ecc017f52028d49b0510a2e45a3ddbf0536c6b199444ca170f6e797b21bda85f13be0bdf035d1386b2cc9c3d8f5a52a" },
                { "szl", "318c5ac548363847dae76c31a7fcbf8b5ae1f50949fbe007a52cd3fa4e025f520827322bfba3a095a91bca71618e2f4e078d1737d0b1012131897b1ce428b443" },
                { "ta", "0137c727d0d36007ce60ca482ffe9e8a24690d12dc5731f3bab16e76ae62c91c464c892ebe3d953d4f14c66f1c8b2d5787caeab4e585a057ac20653cf8863aeb" },
                { "te", "743fa918a89a8c5ac49f2a93d15c6535c287f6959c24db9a2f046a9a241e70ffb96a026f5e83c71036ecaedcfa5f347a9f11244b5208b797b4b7d999083eb4b2" },
                { "th", "28344ea986cf790d2abf3e3c0b1c3df75ea441769f2e78653019221bdf3206c454df92a25f915e7ae26f7cac84a69702dbf7ff3a6872340a2447321e50545f75" },
                { "tl", "66d63760c377fc8fd834a7403e2fcf94e1ead2ed8f632fda16985347e54339e8fbf723256885a78bd5c186667585a8cdbbbf97c78afb37b73e7e381f11488a00" },
                { "tr", "27da794d4fc62c2ef3993609a594c38abbecbfae4b5bbeff425fa4f99b6f804c94eacf2557aee2e472d47e2fe5cb40b026b9e8d4c117642f1bdb446f81b8270d" },
                { "trs", "beb3482ea8e6905e93e3568fb9d96146265d8742b2747e5c532141c9a9fb1171e5129a708c2ae2a0a138bccf2fce97f09b8e18ca63cd8a065260aba020fed9db" },
                { "uk", "398eef7c927b0b1723d0e3923e55041c52e4625f77095a1f2055bfa8b7a072da82ea218b764068d0dd9ab6e845125c9590684e6233b11480aec4665d1ab959e9" },
                { "ur", "3fc82878d0e115ef9a83579a5d12b0e3930c526f184c549018c48e79bc524d790f58843c0465c08af0e8c8dd5ecc08c7a7797b91469f931d8f2be38713490765" },
                { "uz", "f542243847e3adfc5aa8b63d192e7eb4764514b62b75af32356a09f09240ea129dcf9de52f0e2f1e18679882f28ed33c1c265cca2f15a1c75236806434bf6a91" },
                { "vi", "68cc8a59da073663cbdee1b0f7b6987417b14815f0bb140012d2b29d306745bfbfdec186af27fc609bf972c1c5de2fa9ce3a08969b4f24f1906d156a8a54085a" },
                { "xh", "a70d1de3607c094f12ed247f1720f045a709a5333c03bcb873ec0e089cece71a6e99de613d8a629a9231799c0559e8ba7576303e583ac08b90a6f2842effaa75" },
                { "zh-CN", "134c6c38366243a84ec592110a8b0ad79f02fcbfe80c19333f06981fbca3acf1effb24172659a8afab4c93a7ba7003f627f0928e10d66fd939553b61ef9f09b2" },
                { "zh-TW", "d8013249082debf05e3a0319d25690fa02e20e3dccaf806050e92ff86868d633bd8e54f822e7a25e0314d8a40adbbd68e81f821ffcaa65b87d73b520fc597f81" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string knownVersion = "91.4.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
