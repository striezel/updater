/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Release Engineering, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/68.4.1esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "38ad1c57bc8a09edaec154ae7d17fcea4613ba2080e4dd0f9fffa8543083a33f91725fbc06793257f166302c357b784bd13107f3c7ea783b599110e441a87f36");
            result.Add("af", "e217e20f2d21d8c29be8318dbe238ada2b6069d1e172a914386f3e1efe4a8cbc5b8b94a86f3b95f04f72d0576dddb06d5ce0594e071b47931e6a0d00885f35e7");
            result.Add("an", "f5e00a17f635b0fa09e834940556907430c8a61033ab39c5299e3c23072ea252e9e54a5de322964648b431c099c8e204a0bf221d4934c7edbfe53eed32b5a6ba");
            result.Add("ar", "4d31a423b8a3214efe85be5f2a846b783d72d4c699c269c443602e80477c23e85233fcff1a33646c19288451682216da8112ef9364d60c0d6460cd35b6c7ea94");
            result.Add("ast", "e44b08c8a223087b0b56c1aad7a881daaeddbbb391dc24abb5a52bf0ff4fc42b250804ed52788cbe01f99cd262dc47c8a19ffa036273ee77839caa4e275fc3a2");
            result.Add("az", "a7e738081d8162e5e9f04321d92de14cba92643876ea2771c30c5d790b811170b413e20efcbf6d9a5d32f61a8477b98b54756423030a5f2b89b9bd828c91eaae");
            result.Add("be", "35c17861db86748ebb500fd2aa5cddfedb7e81ae63a0d1c96ba9f190595504eac1a76f762c03d44e05c80f5f4146f5ccbb810fa40a5d18cc6f8467129be9f38b");
            result.Add("bg", "cda6ac98c843da16da0147c6d68b70bf21826351caa05887db374cb4943341ce56e745ef1e9d2724797d1b3f2db2ba920298a4e69474b5d8cd0ec73278a7f885");
            result.Add("bn", "5104e67dffb7ab664d882eb7d6334e91b08d3ab681e970704be55309f4c8a427911e64a718cec2f18c9dd53108a7765b9f0788086f9903aa7d624a20d6d1285e");
            result.Add("br", "ad34ae56c73563a12bc624c463c09334884e3fabe55192531c22f38394b6849b409a50ad18ff9f3ec057ef9bb37875d9979c3e274804fe507ea0194ce18667f1");
            result.Add("bs", "23a735cff51463579283015e4731efad495d9e1e94eb3e92db9d384202bcb7da15597cecf580c285a91e093e7b4f09561b3ac726e151346654843b71040b0f32");
            result.Add("ca", "ee075cfbce2c461e1be0bf29e05b10beb449d38f9af40af43f631b24a687b76b440463d81c7ec218d7001be62521f69db87a3b6acbf311607aa8286ca2f2c5dd");
            result.Add("cak", "24c3d003a49e12ba94dcc77bf55ec355e6ce910e157449a103b448ff6129833b58bafd47e56a5854a6b83ea37fac84a05e6ef72da73f76df9112d118b35ffd20");
            result.Add("cs", "b84911c2fbfb9c0f0a7947dcbadfb38d1fe6172f3ce8d4aa3c150fe8da06eefe6468ccf2d656cc125cce6be77697dc3883ce4507ec9385e3fe3f4a098da8fa70");
            result.Add("cy", "12852408f6f159de4c4adef32cdd83c79c6b2b63d461c660e961d5ddac0e688aa3dc46423ec6fa05cc539eefa0d2e0664b4272f7f16cc4cb1960deb0df315685");
            result.Add("da", "f5b3cab9723b610afe5e7d1b5f36e1f3412fd6757f31a0bd5402e32f9a934dc13bee22f4918e2e9be18b870da959f7061f73595bacf2df1b689ca6981a894f8e");
            result.Add("de", "6e6168a53c8d8ed578ef4920a36a7b3de4d648329f5d4c52932355e51ba99f55b0431c17f173eed177b31ca11ffd61096b246a3cf3f74de23d561e664dae1295");
            result.Add("dsb", "ca4bc8882fa0ab4438ab60ac201cbdd3a092fa63cd5fbc23d9697e827514684679f1b03dc0c251c06a485e4c6e6a9a3ac66a8f553e52d838125ff99732c2b7cf");
            result.Add("el", "e68b5c18c64a25fe4823c4f2e71f6bbbb4c9e7fec81baa8fe8441f953df7635bdd76522a6063ebff0cbf4ea52fa1583337ec10bd4b77c9c9e8d4fda8e39704a9");
            result.Add("en-CA", "e9fd2460a867f5564e3704d15e6de96107d6e36178e886e83f85c8fe9538522de6cf85adfd6c616c6728c03181f3b5ef148e850636ea1e65d2aa32913d950da1");
            result.Add("en-GB", "0626fcf748f8150630badd66ae340a707d2f9103c556ad96077f80ec147b80acd828fcf829419efbb2f211703c7bdc0e9d9cafe2bef5f6f121a32b8e68771202");
            result.Add("en-US", "76d61084d9217931a64e0d57a363fbe42d4b4190d3c9202bce3376464f687bdfcedfedf06c5a840d3b1dd6f82188e2be8342189e5b078fe3ce5ae8cb74180b08");
            result.Add("eo", "6d705e1ea630569213e0d2ea5986518abe55a1306a4b2e9d6a048ac9397f680c91ca6a4fb9caadb9ebaff9618567227b23305d1a927924e41912f2e17ef30996");
            result.Add("es-AR", "54f98581d434b14ffdae0ec18cf78f3c7aaaa63af14fcca17a574a468aff6d902826a1a4313794e40f7f389fe93c49b60a9de056a6bc21cf2a28f20075a2eb13");
            result.Add("es-CL", "ff1f362a99c405bd93dafa267a4351dede4b98f718073fd4387bde85cdf81d9b4be85fd75cd478de890e9263ba79e17872446d6af9117012eecee41b8c005f1b");
            result.Add("es-ES", "e1031c7c39581eaf6ae7cf138a501688bf3441f6babfbd435096928d731db8aa82279cde3f3592777d88e0a77e44a14945f6c7f7cd9b1267f12032b5e143b974");
            result.Add("es-MX", "7c3fb8fc61e8809e7ce12b0061f09246a231b7ba0cca009ed00a10ee0e516fc0a3ba69ad214bc66528e0dae5dc82982356101bc6dff8e6f28c4675e18ad1fb4b");
            result.Add("et", "96bddb569be96b5f9788a88d2d49484c0572d8bf8bf446478a7b280bbe0a22a9d782261afc332bdb9db9a661b6cf53ebfa4d7f039fa6f9e24f74f13bcd8c4a59");
            result.Add("eu", "a11e742f757a031fe6c5dcad7835b688cc235200eb5c9eb4a16c12de404c1616d211798c687f5c482cceba0c9370528b8df01076186a39f449ed111077d60413");
            result.Add("fa", "96ab4bc6987735c5376c9961227dde22cf62d6d7d806ea89a6db997ffccd8882e9566f4cbfb8c6cbf665055e466c271bae051092101d3924a6fcd22c5d001586");
            result.Add("ff", "382bc94b023a67acc0e734966e5b8d203d0ee2e471ad5d1173725d72f09b40c0b0ef7f9b9a9b9c1014e534edafffbf7ed499f752482a06bfdbdf014362c74281");
            result.Add("fi", "9354336ed7d343128b68e134e650b1471879c1704510938fe8398e61e9856328278c23cb4973961bd33ab8015affcb639024004fd1d825f580dc98a5a2119704");
            result.Add("fr", "682f9c4e81865165b10511c4a477a5a17a613ff498b1a8b345373f417518b4d0eb3e328d78c30970b965b8e0c051a39aa2bad1d0b2e3ab62aca732812ba28a9f");
            result.Add("fy-NL", "a2546f3b6f262090412ee34759094e87e4da9032f9e316d7958326b8faa1e79b31ecdad27c52efdd6d877ac61a0252b5dc370d34898d08479c9ed058cddc0039");
            result.Add("ga-IE", "2c3e347658ef0cc4efd65df5a4c257dcc3ab78f0b335349ebbd36c617f6aaba219c2cfdb0772e8bb2039b13270c913a3a6d0a20e5a3e18cc5e421b80ef957a38");
            result.Add("gd", "9f30330c928c00c3fc2552cc12a1609a1e9366c5734d4e0dccb0206d1d59756ab41635e265b25194d08b689bd39bc632a3511bde386bfa0f1368cf064c04ed08");
            result.Add("gl", "043cf83c082b3520b2fbc79df53d1f4206f2032c197a032b2a5a82993596d64f1eaacee769a396d4dafc884fef83ff03e47fbad221a42fc19e4f5e0da5b2f2e1");
            result.Add("gn", "b3506c66c967b785cb56850d164deac33d16dd729112be9f2fab74a51813dabd571d3403b41b9a1826e11f2cba4c043c168489a6328f15f4432ee7ff76718e30");
            result.Add("gu-IN", "dd85a6dde53672aaf80460cd4f5e38bba41b2f5a911a132a6c4949f02421176a2aaa07bd6d6b13abaceb06466351aab8166bd46bfd0bac52e8c0092bad4371c3");
            result.Add("he", "1eeeb12c7cab5cf199c40bc3efb74bab7320d5252a52eba086fe44093a8da25a55504bf44036017645545274fcce77baf0623ab47ab0f2a2b04c5e3e0324df68");
            result.Add("hi-IN", "3d25a11413133adcd16ff2789eb824d6adb459f001e83424a266fc3cd77815a648eb432c08237eb8e8d5f22593b6d01cf4435525a87afbfccf05736a0d187e43");
            result.Add("hr", "4c44cef0279be5ad6e56e7814d036f13acc01d65feef7b68b6b83e66a52de63922087076be297b6fdd23728290e583635a3272faf85562ac317979f0238e3524");
            result.Add("hsb", "1d8ce22e6140c76929144fb6e37d62b82b45b1dad2d6c4984c071db98b566438269a7981edaf84e87a241d34abcc1fc7a666d40f4253cedca6e8c2d6a9bdf8ba");
            result.Add("hu", "8c0a02c06d99b1d999a8007bc6f47446466b350637327e24f9f69ac878dc5b49fb269dcfe26d17763cc4c79768510202b0e02e50b687011e2bd846363c48a412");
            result.Add("hy-AM", "ee30094b01e3cd4d2069c4bc02d02c7111cd100883485d745e9df55a7b7adc8f07286221a3e5d73f54fe2e068f13c78f31f069f4fe4133d0cc1caee7cabbc575");
            result.Add("ia", "19b2a78803017cb1caae2547c78328ff961347396e71c7dee5ecc8ca85b2694f8b9fe3daea59eea2e2170a4fe3e1a9077b5115343aa464bf007c2fa122ae4b34");
            result.Add("id", "ef2874a9bee769aa797e15cf8e032be5a34c84a4fb2b1b5a3cf477f47f8e1a5dee513f3f08bb7123deb9a24f813cc0d371240c9db13aa2f3d0f8d15209dcb33e");
            result.Add("is", "47389b2b3d298c52a0dd76f85797a65be8d9e8c6fce46b4f9fd318467c2e98c276a3cd81a6e61de823acc2945df8c06e77538c8eca45ba4bcf125d1f10865b36");
            result.Add("it", "9c524e21bb006f3238242500ee3a0bc4adaab0d94e6f7694ca6539db04e0530f3df747023cb551069c02a016d48985a31f449bb94ae87ee9311cfee57a61763b");
            result.Add("ja", "971341c79296687584590180665f9dd803493e9ac0caa0425fe31c585ac628fafe3a19849c9f207099af9d079ae27a24a4fd88e3e333c6f4f34465969e607850");
            result.Add("ka", "8dea7809f5f05b32e4b7607cb686907ae8fe15f6e453fac479121a55fae3fb1e3052e30aec2345ca30972071dec416ace5d4d10ca2dd4c328aad3730e8c3232f");
            result.Add("kab", "18d96554fa476e1c37b54a6a9c6e10476df3af653a9c3e8a55021d3805837f197f3d9c790a7fd445fffc81b864e17ce3801003aceda654e140127419fb9b5087");
            result.Add("kk", "8cb463975440111126a8222109f00fe50a09bdab08d8f802d69f6e7032a38ea23d3c918c7222015689fd4a5eab76a823e16c616cbef928306978ccb6e9c2ad62");
            result.Add("km", "8981ec777a897b8e6e09706ab0c236613722219898f8b7c34b97299d79317e7f578f51fbe17006ae2047f5d048e8c29f57047eb324bd2d037cf612feb6010c2f");
            result.Add("kn", "dc864469534c04bbdd9f5265c2549529dd012514c853cd1cf2bfae4ced45ff3fdd92e27268f9eadb495fabe07c9f36dd96aa8847ecbbc6e059d2608d99065ebe");
            result.Add("ko", "531eb77ab0ab1e2a5e247377710334fc7748d1b7acd64ec023298ae7ecaa6a20804b0d0451ef40ed7e21d854ebe2b1ef0a46a256cea9ff8c455fa210d4a1858a");
            result.Add("lij", "445ae472d31502a77ff0da458fec89e38c6eef75cf75523534390bdeb984ebad1e1dcb6ad341fa1d0400df2a213832ea57db78baaf3572634cd589f1f961d572");
            result.Add("lt", "7ec2995158cdfa70210bde9434765964de31511ca80d6e577d8e19bbfdac8f2ccb8a0279326641f1506c0df648bcf4ca56651b3cbb4856f5b6b16d5828ed6587");
            result.Add("lv", "16321e9138972b3825847aa69f3e818fa236a517fdac0004e04bc27ced87fed2658bd0818c97c1164183d2cff886ee735d6a5e5f179a6faf85152d7f99a6ef15");
            result.Add("mk", "21ead80debb9b3947eead4e998ecf2402cd0ebdbf460f2aa69c035e7d18c7cb4b91d367e52d38ae2039f7b52ac082c9254aa8e07f30ba76eebd8166bc6071f9d");
            result.Add("mr", "b26126b51801f6048a3dbddae6228153281b7f8b8aac8183dfa119a67cda1290f61367e19925808cedc826c86721632b0c8a82ee86c78af305db01b494d3c907");
            result.Add("ms", "d75647703b52fc19e4bde3ee85466d5fa1d404773c17fc3e51ed380bc73111ae52fa64bd47e703be784ce972e9e0f5b8f7dede28046b8eee2a5612351e32c7ea");
            result.Add("my", "42f275fb07345e441b23ffe8b5fa6b659235917133c5793737d1cfeeed781453e3b866ffa41c89c49ddacf7a4d3d0cb45b8c65df3a58800e64dca2e92cbc7c82");
            result.Add("nb-NO", "8fec3be221f2f8118dcc726e57d4b689a4b0daabcae5e6b61b41dc83c948a4aa23c3661456ef0aecc9f5acee88230cf09cc55943bf5a64f1b0b25b5ef951b6cf");
            result.Add("ne-NP", "f26b08129fe4333549cdb1d33cfb518b69db9348f30a525c3aaba0b3b731ac9bf7e266fcde005108456f3f6766679cb9265b6366001800db9b39197a09a0186d");
            result.Add("nl", "bd2624672f653595c21dacb4cccc8c48bc5491d4d4ac6c2a21d8aff207d1e46da2fa2e962b0ef383d64d63b3f5cf9ce9f9ce82892207cacefd023ed71f377b02");
            result.Add("nn-NO", "d92060753b37b75a63135128b5b435a640ee9d28ac5fc387964285d11cf5cbd420376804866799df06bba3147217577ecb02920c4827fd4a0ff5fc1f358d0e80");
            result.Add("oc", "7318b8fbb68fc33dcaa747d43e80842ac42bc9378e51e5fc4d29b512d1e66a442773fa73c1e0ab72bc9c9eaadc527b386688ae40ee4251cad0fbd35bd9b06f8b");
            result.Add("pa-IN", "5044f82060bc6b85535427e6a5e2631ff698e43735d066d34892e2e35492951580b1d1539a975a7d6796cfc26fa72890427a8688ad1afbdfd91549837dae944a");
            result.Add("pl", "c539f4349711ece9177b64dde6f74dc1cd241af28522668f2f5688eb85bcd1f337f2cf60917f4df44778ba1a883732c40c90276ded81aae72280000166b57d64");
            result.Add("pt-BR", "184fced3337f6b0efec6550bb1831c8c216047a86bde361b300bd34b2232c8781ad0beafd0a4de536acc75dabd24d6b8b71b26056ba1111a6f3bff741015fd57");
            result.Add("pt-PT", "3a59be97679032c53bbfe3b1aa96e207cc720194efadcc8ab5dcdf7a404a971c1aa4634254ff6eb42691ccaeeadde64c3994d8d32fcd09412bae320e1e886527");
            result.Add("rm", "52563dc36bac1784047709d4a53d95a4953026f11b9ff96a898855c74b865773e085db3584144c03b628d336722a49f7ecc65d89950966b1fbfb41d61b43d628");
            result.Add("ro", "efdd594b738ab29e38f9ccabc30f784e1e94006de5021ecba871ebf762632a8229753baf0bd183bdf681dbb24136fbc046d026d53ad8d969a49f85001a715e82");
            result.Add("ru", "e0b9371bafc4ebf1aa7fb3d3e035fb5f49c8239aca93e17e67117a2ff7f6f8572c9fe8ac1b4edbc16b717892e8d27611be589683dc185dad75c3fb3510b799bf");
            result.Add("si", "2222bf1fc5e99e171ec1a7b97b31c50f9ba2501e58b28c79520b4422ab6f2f8672fcdc0db7f6d3abc8cc599aeae91c3ada1b3f2ebdc48dcde6a035817fc085c8");
            result.Add("sk", "cedd78eef7f5b4fc60a2fb9634bcab4c2147689d773f657196624d79151ada635e9c97669de73aed3c7db7124f500700a6603f85448ed1e59c413d9300af6cb7");
            result.Add("sl", "ca5b8d71e68b3160aed7b88d6239e9bcaef754b3937f4e8aebb8f1eeb16ce5250935bae9ca653f0a9e510430815d649e4603dbd2ebe5321b38368fc8143d1918");
            result.Add("son", "386a9acee9b6e62b20f75ff24c1bd934608dd59029f8644125c48aebba7a75a7decfc4aa754d01147c619d876f6187351dc085e2c31e0a5f59b188a31b07ada1");
            result.Add("sq", "79894b23f23cf2828a755e8d59207abd6874d4893e9b5f2f1e6f65e837b6d87492f358d274bce6a25ac3d2f8758fe41957738d31a36656d5bba18ebb7e468321");
            result.Add("sr", "f7212a12d3b8e5b51a1e84457d3c40c89f518b4f1e1073e53921fdb21fbd03b026a04532ddf8505370036fdf601fb418a97cc2f8f2e61d72c94e6786f529580a");
            result.Add("sv-SE", "6458b4712b5f686483357a68cd7df149ca83832a882fb2935020c38ce2cb42bda41af8f7d6871f3c0da7d52580c33dc7c7c744ade42baad3b34fea9a3eedca2d");
            result.Add("ta", "30b1370aee5bb50f7977753dc917338cd24e03f76d65f00f86509d7713c879bd3f4b2eb0b42928294e6239f4e5e67ccd7b5607ea74201f9bef1b602c7743c550");
            result.Add("te", "7dd5b8358bb0bf0a89c0c20c7cf32663ba2b373a215b87a859875cce3d842702b150e2ae22022742951ac60537963dea95219b93d3af57bb823e13c465b06e3e");
            result.Add("th", "e8b2c8248052a632e623cd0e90593971e4dd5ac55b4222dc7953dd0af8c98abb3cf9e0060f72058cab91f990de801109389c97e76b84ba934fd797b81dcc2261");
            result.Add("tr", "ce33fe3e0c91f8415e8233dd572925351dd045e726b2576ac09a0a0da6826f59061039246425855d30e29b284124f13f4665b11aab9a80be20d8b9fdaf273ec5");
            result.Add("uk", "d361d020be362ec4768660430091b6b6075e20f281fce9cb9320571934f725398a69c8d7c3924e6195f09b1e19cfefcc517ca9bb09f95be898368f47b192d835");
            result.Add("ur", "ce0ba9da5b042680077e9492593fe95fe150e884989c90eecb13b3accdd87d0a7d7882d0f0c17acf7b1a668d5a7cbe74d86ad9a95c3f5a73aab33646c0d29d1c");
            result.Add("uz", "45b6c32270a2cba6fe18910b362e08f0cb9481ad10750187163efeae058cc9a4e587897a290f44f5a519451d517f4c8182f8e2bc64d51d7cea701bf49bb2d522");
            result.Add("vi", "7c92dc2aa8d4e4f01b7ad850a16014c2bd8879c7aa206a1453510d0cf7f2f18f75a44dbd68d5f98a67b29239df0f26fd1a7ae4ec9da39cf24e7a50a848c02bbd");
            result.Add("xh", "389fdd5347ee4a6f60a8db03daa1d1ca265f282f0bffeccc23c732810a3d2c37dcab41b6f568e8e21ee532c8b0517f5da7beeeaeed86989eb6f182d808cbf88c");
            result.Add("zh-CN", "4c26cfca172fc31c5a29ac765b4f90f63355b21482f74e0e7429ac02e62548c9890797dd12577185bb3be7018bc97e40dfd392f34dc9effbc38b3bd58fc5e3bf");
            result.Add("zh-TW", "2dbd644067cfe948e86c3acd74fde3f54c3f7c6f04b939937de0a02ee3b3bddaae1e6f1a742f17db4c4929371f63c8fcf6fff499f24abbc67b7e8af0b7086bee");

            return result;
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/68.4.1esr/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "ec63210fce59aabdd70bf3d1bcb52d981881cfbfb62eb09a0e6b4d3ced82153970ba06fbce016346b1df1d4c99f4e563ac598566c358ebe3c3d349c1f538413a");
            result.Add("af", "4a09d11f2cff0c349bdb255c921895152af2fcde5ac3f11489017e15d35257b7f70fbf9429bedc114eff4ff28217a9a011e4fd261aa11fff36f46b2c05a84964");
            result.Add("an", "8340bef4c9c04cf00b94aed65c9991d4297a55622762b6f51e3221dfa1f0066e43d32a1dab9c233d97a2ad62be8e999416f6077b3f57e86e936da1092a7b37f3");
            result.Add("ar", "8e7d657ef47167ba1828eda479e9fc37062d018b7a98dec9c27bff0aa9ad8139c36d7b78f82d5d67c086b5aa3727838467d3393e803adfd15290eaaaff0049dc");
            result.Add("ast", "bd9435668eeb250a673810b840abe0dfd49c79c55882607c8bae008194d0983935659aeb93b15fbbc4a412fbb9a5656938628e2b94c1bbef61bc2d54ccd10a03");
            result.Add("az", "6847a027ac399cb0e83b904d467ea5595740f4c4f760209634b0c9eed492854332fd12c2b0183f5253b882b3ac11e2b0001d78ad29fbf06f0e4a059d4c769e67");
            result.Add("be", "679bd98bfee19f556848cc0c1f96002aeaa673305dcfd038b79b2ea32f335fb2c1f9b5867efebaf8062c0d65294a42c53554eecd1d12029086903a4020e3b652");
            result.Add("bg", "13d943520026ed43af1ccf70090ed83c9aaf93c25cb9b43635f60117d4f7ece72b4a519698c458be3db5726bf23cbf09a41bc90bf451a8a850035edd857c3f7d");
            result.Add("bn", "ad9526013cfaeba988e73526ec006aa268434d0f04bdd62d4e529b7a89ba7876f79088a05a95af015a8341b8a145d155fcf06ad8ba0e533c1c35df1eb448a1ac");
            result.Add("br", "e48f7af0f137550c5f8cf797fe552b0d18da6d13321d942ad8f37fbb041bac133b1f53fde1a354004ba884f61d92393cce1cf16f0288c4c0d7d6cc09b31b656c");
            result.Add("bs", "7188357eb6b967d03190f92e6f93f2c73788c62fcf8f0db1f4262a288a5fab7abdf539d155f0a9ea946cf35e51236ff6f5a00e16c28317e5d90f8b0fe6b3ff65");
            result.Add("ca", "5f810c44e09dac73149bf7dd4bbe2e2b6b49a506408eb717f9ab7846989d6091fb6f78a037f61f08a0145ad04709efe4c07a40b564fbfc5f17caadb07c3e6eaf");
            result.Add("cak", "ebbf7d1882c906a97b41907223cf6b1b7468f4f5bdb19f4931976440a18376ea8fd7c1ed7dd6b5c6b2fe4b51f9d866fcf4e54bdd30a6b5189b1ca41dd0257079");
            result.Add("cs", "63237f5976cbba4d7a38742affcf564a4b1494eee1f0c85a8cee0eee73502b4bf067f48ca6092458f8a37dc2cb3d3b03f8f8b0e6cb3bb305bd047de8dacd69b5");
            result.Add("cy", "3f9b6189148080bf38d80918ba992f801bebd4fac856222ad3b7b31fbe03a3d241f63782dbfed42f93d9823cd88dd7356d55357d39a00ba1cdf647db1716837c");
            result.Add("da", "540862ba5d43b9bd453286db98a4914fc3c6cbdd891ef7c31192442597afcc966ced5072aabede1755c7007bfed3a70af92e05b8d93c3259db9191d277a92bec");
            result.Add("de", "8ec8e1a1619399e0803f170f7bb468053a32abbd6ffcbff832947431ad4024c4c5e3755b15312a6975b4cff570b3fb8fbe90d430f09cecfcddfd77219b08eb0e");
            result.Add("dsb", "c6b71c02027bc5539c70be45a91c830dbe2da6faf36772a2744104fd974c1b890c168e05f6c94573b201c8be25804adc84362aeeb73b01770afd759a9b235ca5");
            result.Add("el", "0781dca87a9fa5e1fbd48aa0e7ee5ccaa4f8694de3c6763120445ff519428a03a9a478c5bde714484d60272a17fcdf8c928d48bb9ccf6f9545296c0c16be9f83");
            result.Add("en-CA", "0699e83e6395cbcb74671bd849587a6e42e8b3440270beeba1a159498d48fbfb0a31d30d48e3e88514944d170b375ce60e123909f6e92b5ed5df5f189163cd49");
            result.Add("en-GB", "1a60ff4034c4b72c505fdd86ffeb8f498d757d269a95cbe5a300420c55c8a432accbde31cd046c6dd3ca7c499ccc619803d929b699f0639b23373e0f2b88b7f7");
            result.Add("en-US", "817fab227cbfb8f8a75b5f5ef644d4b3d6ff22f3cc4e981dbd9372d82810626821890c0726b0f43a344d74898d3ae80c3c4e6597682c9d2f8c0153bd19d587db");
            result.Add("eo", "95d81ce0434b3b54def823fecd0573232027672905362a50d8c1ba03e6bab9e69b60ff21e2a4dd1fc860ea05cb96bfdf8c6623cd4ab9300bb428bbc67331288c");
            result.Add("es-AR", "ff569fd9d4655b6ca16d53168eff0f6d7801692728f1dd5cae63e3c9dd928b4b70d32804bf1005d05646c7a81c9151d29efc35ddaf05a97fcc9908238752e229");
            result.Add("es-CL", "23d3cea64d131cc4e58c97a8f76e5706f6966a0de7b5c3a98389738e23d8a2e9ff8dba4b761c215f0bf2e427d168ec4c48c965ee850047321eaa2a66a0b589a2");
            result.Add("es-ES", "962b679609d27aef5d00c40adc63fc293e059d701d5fafe8fb649d6ee2f9063ab9baf1a8cfdc86cc57ecb9f53f34de2248944d951771180bca8a3de254a870d6");
            result.Add("es-MX", "88728d2def92832c5318b6fa87949e45e8756fb2212f95fa0fa3601a9d000a2a656e2eb45205c2d05236edd3cb5da79e741c5d8dd0990ca9ca30f475138e6789");
            result.Add("et", "f56d1175c30dc11f23f3f69c6df5f78e6f0746a13ddb04e6e3bf76e99b76e74cfa884e89f8910bfa6888ac854925ef085f64deb57c2a3d9af7f19f91b2330413");
            result.Add("eu", "5c861c32b848762a060bd59c4588a65c2876640d2a8a292e15775990a4a38ea0e8e6c3ee7907a0a8ffed13d2f00a34b09afce8bfcbb4785a0d5682e888358c83");
            result.Add("fa", "d3a41470b6930fc4c094f59b8f83ff15e3604a8521d668bc857dcbb9712aa950e79bfdbca1e102db7720be31cc6b9c9aeec15210b86d293039455cce0351e65a");
            result.Add("ff", "db26c8fd196a4200039a1fa7b6781ff8407129e33a0829e5534e1eecdac87c34d3372725c71e5ebf3437584054da6f97a3a3fcdc6dd34bcb3fba3736631d5c8d");
            result.Add("fi", "5320611212138182fe29c0cc3b31e24fa2207e7e5a5b9e979c6558ed918be4638f6c9facc22c515569a14c8cb56a7e49d4286132ebc347a159eda26dd44602e4");
            result.Add("fr", "c433cc5e12dae792ee84ee8810d97daa3396e6d5860957be72214fdf500011e19703eccb77748f5d8b7e6531f5828b38fa2e73ab7c0e43c8d6effaa189cfb6eb");
            result.Add("fy-NL", "c76985d38b81bf76bcadf8474e28a8edcacfc638a0479a26c564e971da6a2e6db1915e4c82dad6fc51ffef813eb26a210871aa514c0a4a640b254b93b33d1e8e");
            result.Add("ga-IE", "84e89006f656ae4832eccf49664909666368428f18b22c8c7be02b9e728773b279c0df8f2922a6063b285f14f853d88dc5f1fde0fc9c9a9fe3e9395dba90aa63");
            result.Add("gd", "d8cb01c1b59fbe1fcb5aada53d2058be40ea5ab10229712d47088063edbd501aef8f28bad118a32772f6c91afb585d0e7a491d2f043b7409a06dfcdb2d58ab0c");
            result.Add("gl", "b5574563a674d450026328e702639ce7ed57dc15583ac00a6f9b4903c046197a3fd66c9bb837c39db778e330603a7589bf576f37aed9d94e504a1b6b95337546");
            result.Add("gn", "74f5c1212375afd74ad800aac0f5c1e8ba059f7a8127c4dbd02a1794a79a380107fd2dfc67aca1c09be3bce83635f72f49d86b353b9dba1fa43d425d5dbf2c64");
            result.Add("gu-IN", "ee24c98014933d41ee94a4bf726f156fa0e3b63a598a63884c13af0de136cf7aec2ff2f305f88e276eda14e6c60fa268965a18843a7750c1d06954107b947e82");
            result.Add("he", "e8424243efd1ad13424353695ebbb3f0da3ad353df909cd3b5cfd95ee5372e21e6c8f8bf0dfbfd33e7c7ec6bfaf1591841ba9945b991de0b320cf4cc5cb1cbda");
            result.Add("hi-IN", "217c6aa9d30d521fc7598fdca840d64fd211f2476c7d77914b759feadeade84489e4e2a5d65df5c10e736a8ed3907330b269424e67f6027c0c5b2ad34ba7b8f8");
            result.Add("hr", "e9ab6e4991c76cc0b1937fee7f9d997b7db222cc81e8f9b6c417b2f75b5934c33e35714334a5b4711cdfcacfb29d7f9a7943dbab911529de684ab0667cadd72a");
            result.Add("hsb", "1062eabf58d02b6177c0522359eb423154851129c8c439ff9dd6cd4f1f0930872932f62635f473757fced58bbe680585778a4bfe8809f93839a37daaa2f01ebb");
            result.Add("hu", "a135ab94aa734951e7d15d9c46f295766c2f9dc1cce9683a4a62fbdef519457677c2a5973b1f1591e017a411edd0d74f62ced7896a4d72c6ceaf4a85da245eeb");
            result.Add("hy-AM", "fa44941b7fd53b1d9b2aafcbb2bf4fe8927c64b680fb552bdad4901b7f9dec189c994ae5c5287a5d157c1813e6a4e415a7de7ce010b727d8e9328a78f8b147dd");
            result.Add("ia", "bb4e476bf019ac604a98e26f01eece21c5beee230995e370459fd34a40bada95cc71ed0aab27e10479b94c47c055ab4416b94166d390ac30e5ad2e8f1b04596f");
            result.Add("id", "75d7649dcd6f3869718d58fd64ce103eb624d7e4abb1105a113e0c909e33e43bf564b021122c675d3e980e63870ef31e46c34b8277768459c05b054090672668");
            result.Add("is", "253bfb41796b6cd961b27d64158d64be9feb32dfaa883ea94ded38976641401a378866868a1414a3173118c9cbb7fc5a43d45101cc3a18c0e9cf8ebcda293a11");
            result.Add("it", "e569f9de177bae8a7acdad44547933316c8bd0ada6a9a4b42d50d2e8cb04813c78a3cdc3ed2267957319f8cee74f9e22a28a0092a8062265feabe13a0ea27f9e");
            result.Add("ja", "6e6320cc2a34ceb3e819200441d8009a26a99ef629b1be5ea08ce29ea7b99d519fd8eb873a13c4c9931f272dcabe054263b872d078c510b7177bc74378083427");
            result.Add("ka", "d0da30dcb49cdf6dd6316cdb735807fedc5c410d47c7ae6c68df9f5c0cf53316b9a30b7d308cd794d49eb4fa1a8714f70d80e4630ab61d0f119e31e557d5c0f4");
            result.Add("kab", "e99b2af8652e7fd7e8fa8db2255b73ecc28103e9b934d6b05030b80bc0600d6a2558ebfab832979f0b24bfa70006a9697942feab2b31367590ac52b12e4670e1");
            result.Add("kk", "cb50a6f3e53c1b74c96f0dd5c27a75a1100b5bca321e6a575ebd8cf6e616914c18039a480563536521bd02032464097c72890de749e6ac16f93abed5af59da49");
            result.Add("km", "2a32f7e5db21c655eb051f22a27d92901e2b91d075c723c90744de1733c9ea970fecc8ab340e3a4434cbfa9d2a80dfc4576c704e4f8418eb77b715230d3511b0");
            result.Add("kn", "e1a98ee243ec2923dbf07caeac51121349c5ab303259996f0b48bbd7906b0d9dc6715eb5c5d35036bda727f765aa108c868dfe0bb583aa97bf0e21e6d5f1e982");
            result.Add("ko", "fe31ae73e7aaa0af76e02279a3915953565b4e312822f50f6027a15b7faa1e75726e1ab317c25d685605ca609bb3ea05b06b4f0b2bad11f636aed0cc4e7c1ecb");
            result.Add("lij", "76fd5a84c715dcf658d73a4c8888b4734c9ec02d7fe916a98c8e4eeb394734798ee6f27d030075cadb1aa1f871f56012617e37806ddfd246ada8e48df98c0c1a");
            result.Add("lt", "4c1fb6533b0d0754c34147f793b9db56ef700bcc6e8d88b4ba3522b8c797315de7ce38920e3aac823a8af590d50ba0cbd1f30254d3220d74f355c18dff7b94d0");
            result.Add("lv", "42748fb39df61a33a29a845b266e2aaa7fb85be0015199a3be7f1532a133eb8bc5dcd74324a43ba17785a3b078b6f4ce9dd8c7aa4851319d21641231054e4412");
            result.Add("mk", "5280b00270f9c3b19d9c326fb1b184f3aa5013bb39370e18d4d5d61665798d3cc340136fbae470da992b9e771cddbd1bf4adbf4748227e76fe882524981eae13");
            result.Add("mr", "d5f7122038a089ef09e33016e8906a04fac0fad0536e5877d55216b1bbe9f6da2f8ce5d409538c19821e3e543ac85af1dddfa788e1418cc797a945853a9c5ef4");
            result.Add("ms", "f0d6955d98cc44899c32f1107f0894e13bf4b0cea69186017a3fe75dc29d391a1ecb460164a75e87610b4974d341c83385215be50883a3ef69df9a2f61742fa4");
            result.Add("my", "273b7190b14240765e031cbe395dbea601d9742de50aa493ea000abdf8322d3fb02eca463983e0ad8271c9023a138f2cc441557c0959b3cdf6c3aee1c5082b08");
            result.Add("nb-NO", "cb4ff0b016ce1c306e5ccd1c843d727ee59fa1191a0af004dacc5cb8ec979652434855095aa85c494776e44941eda7e9e702d28c4d24a064221d8b7c4b1590dd");
            result.Add("ne-NP", "4d0939ca9bdfdc8c6d4e2c6625dd3565741a3fb0e7fdfbbc0a0c09e8049d132b08440889286b4cf148afdee5736647d97da71e824f4a82cb3263ad73d90b855d");
            result.Add("nl", "4a9e2e8ffb15a24fd718783eb73afd75f8c3a907df88b77f4de9ad0a1904de48b180f9fdd2946670310b8c3432e61ebbed3a5ed0a27ac7392371dd9c2d868313");
            result.Add("nn-NO", "b714271941ed4761db8ad5fbac9618f8059a9d24d6aaf9204cd7dde6a80a5d20631eba0afdf9b7fa316cbc2c1d3d32b50b9c170951108aa417ff81d145af9f65");
            result.Add("oc", "485574249e4d9b2db4e5d16dc9af923e0c982973d423737d40e95d7a7c91b488e439ffc5a711e8651237ea86a8e131d6f1bc4ae6cb0ce667c2e69fd501bba6b3");
            result.Add("pa-IN", "32ea65fd7540d967a8c3bd54a4ae44d9ba93a6ff1546c9dcfa1d8f1cff070319a50462df8230439d53cb204566e22b03312d6855b2302fffceca8e093cfea2f4");
            result.Add("pl", "e6387c0734296ff2f2fcb21e9303739e792c48378e0b3a4d951067694fda933083e05fece9227fe2df5eb49acfe09808abc82eea4439f251aabba1c2fafb4b19");
            result.Add("pt-BR", "b402da5cb205371bbe41f04e2103006fd3ed936d244fd05f167ef23d9f860a11eec0852e5880f66370a3364ee268314f09d1b2ccbd26a8790e4093578c50acca");
            result.Add("pt-PT", "48b75f76b81c98b997354725979453bf1e0f516569e2733a6cf1fe600c27218965cbe48a5af5fb5b2f4c25c792d79817415c5f462825fd071b3d237b88cba734");
            result.Add("rm", "dbcce2ef44b6ce817cc7303cb17ff3d9976154b6f00ae2fd90887a63e1feddf2668546a1f890b742e06aaf48c9afcd1eb4fcf01929a5ad2e5bb5faed3f01081f");
            result.Add("ro", "ece7e41d974dc0e04d08c0abc8393949cefc6bb6ff7ceb4914f2255a0e66a006ed75edd00b27c901b96be91b65ae5c89ef17a1a3d4c72eb2c282ad85293456e6");
            result.Add("ru", "20e33069524e04b05ce47fb96d8181945bae0708ec88bec036f85de499b21acb1eb37182a06a77d52d567c0d18e5043df802839d2c47bf9c439443f49b96428f");
            result.Add("si", "8c7d8be9d64fa2d3d700da540d918a74406c3d2207cceda45b0ff805aa0180dab097f6aaa227d9cf8b4ad3287d63da5c8578a71d0c109da90325f104e593180c");
            result.Add("sk", "5ee7e606946e775415162471b83003d6f93a972a4253e7daebe9df43a67cf8d8b5829a35501881439b13ba7e74e565828ba094be6b09929a06c0a42dbde9125c");
            result.Add("sl", "08afdbc62c2676ddbf83e102637a58914aa87b5981bfcd6d915f85bb84c9d120e7fd3633dc29758cf60a1b3a750af99fb88b75ef06201f9d2900cc02d6a875a4");
            result.Add("son", "e182ef3cc79eb342a75b4f06cadf02f4e57b161f460ac24f4a1b62b5c7b4abacc7ade9cc3958f2a64ada551b84dbf691742341d4a8f650c46ff03ca5b1ab9a90");
            result.Add("sq", "bdb9f7a0b4842ef9eda0b093f2a65a1ed7ad39fb5c4f4e70ed1277dd17d20d0ea786da7be47304bf8fd5303cfc597d70b2598c138bdcaa8eef88eb08a0f4b3a6");
            result.Add("sr", "a85cef9b18a70888b4cf6c64f8b0269ef092bb6b19495fa0780e9d43dcdba9f51e49b48f78851283e9b33c7ff2d4b1e6eeefcee1fdf81083db6ffd37b5e96368");
            result.Add("sv-SE", "b8bce5223eba8c58f51a7796ef6b07875c303d282356fa4023d8906809c77d49b1e83b4e26e38f54f28bc30c3f560db2bf89b203542b74f4d83ac8ba9cb259c1");
            result.Add("ta", "18f50650c6ed80c520e65b99eea1a648bac3ded08c34a7a2c3958a2c72f2c00825320b6906671268dbaf08058ac5d116580ade6206fa7d3d87e9d2b09648562f");
            result.Add("te", "770742190cae6b9581d2ade369326c058d1d55e9ebccfe63638b8c6af80eb8831e4ffbd3d41cf2ad1db6f1de8d726e353584041823abbcdab2a6d3e07fa44dca");
            result.Add("th", "273131a9dc7a4a6477ee908c64f046bf6b8ca33e1c05139d8aa824994957295573579f651ddab38f91816483ecd95cf45ad2e7e9a0909b25b705aa1ba5e832a8");
            result.Add("tr", "2ec879d65dfc117b1cf6490181b5f7828b05c0b6c4a14d27a254c57115b1ca52f07217464d9a5c1e1a299d9bf17ed40b38c3fafd267096f13afa8e311bad3056");
            result.Add("uk", "05d9692f16fe206bbf0c27e66f06e84344978ea02a8c5e16069a9f689869eb4ad3f1a6c5bbc951d66f8408b973a4408359cd523a8403ffbe55e9f7d475ec0e69");
            result.Add("ur", "12f6da816cb943f0786871c505b664c965ef77d37ee28386c62d127b90992cde866c02b42cc56314e1f7231b99162781463847cc8d515023a6c08d9eac772162");
            result.Add("uz", "e0c2a1be0b21b0ba99d94693adcd79365c73a08e64b1b25899fde8583ad3289fb14544d019b6d302574b99224ea87a347bf30fec861d6ea50ec3c947729eacb2");
            result.Add("vi", "1290f34bc3aa285a2aeea93871d482869ff73680e21080e3e8c55071b19180938a9bf66898c1ed75abbfb4e50c3fbde1bce621cfbbfedc638a5f7ebb9a2a6b78");
            result.Add("xh", "9603aa972ea2975121e5bf213b42259e8f5176f19a4799496a6049948868b2d7a5e66e0aa088a2b1e86140e315b1a8ca8fef3dbd98064e02c7663c6c0ecfa36d");
            result.Add("zh-CN", "d93424e967ca6bd438f4d916a09af494bb342d2b4c53a005ed59576bf91fd262f992c518416b12003a94c73a23420edcaa49fece76af7a6a1bc8626e28730444");
            result.Add("zh-TW", "c006a2ffad3cc4719a3799b267e22c9ce48f15757fa8b60a6e4399e2c8bf6a843c751d4932b71310e9e3273853f6da7071dd4309005705f6c7953217bd7fc1e2");

            return result;
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
            const string knownVersion = "68.4.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox [0-9]{2}\\.[0-9](\\.[0-9])? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    publisherX509,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    publisherX509,
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
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]{2}\\.[0-9](\\.[0-9])?");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
        /// the application cannot be update while it is running.
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
            logger.Debug("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;
    } // class
} // namespace
