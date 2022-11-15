/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/102.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "4a53b09caa043a7e9fe51af168f171e8508008d16d0b4cec9cbf400ab31d1653b54e5dfdc411584d5cb1e797bddc773ed425999f58f6ccb00a8885e564c3ee6e" },
                { "af", "603929606597000feae20f402ba6bc7ca27f484fef15d332d56fd70f375bac4b69208f09faa5646bbe4b1ee5b0560ee6aac2a769aa7a1f1359276cefc77c919c" },
                { "an", "d3974195fdec52ddfa06db419fc57a8d0ecf307a426e3523a50630e85790a0728efb0a531eb0ab9974f0cadc0da3891a75f45eb16797f08cbbedde683311de6c" },
                { "ar", "560a74e4772f145111ea8462fe03c7d566dcca2d6a6696ae6f659fadbf368cabad0e5c3731a3e0e7f941ce588acb75a0ea9f637ba2719f883cc8d20ce84a36bf" },
                { "ast", "66e1f8a77cc1f305a9daa5d98dc0b3acf786869f42c8424ec8fe1e6f159091827f25bcfb62be400a2076b91568b11220c1d1a9cc72fd86dc70754da20a51f5de" },
                { "az", "480bd010f694b851dec8d3a3ff39ef5470a2aa8aed0f8a7714e8fac0c60ebdf44dd91a411be05490ef046150d35a489338745bd5118c5e43b8837e1dc76054f4" },
                { "be", "abf28e8411899e24b79c1dd90ed1ddded6a70ec072f316ed7367deaaef688e5e520d5a35f84dd7de5c96e6e57d5bbfa035de1adbfe976fba0a334789b316bb1a" },
                { "bg", "425d2d29af95bb0b466a1354ac148cea77fe3f40007735131a7c8edc88bab57a386734f472c7534374534c792993ee3ac8d6b81fe382b4d0589f421f1324a6be" },
                { "bn", "f27a2f11c719e301be08b8010d369708f47172b5a223c6d676405b005715df10bd4da2289a22a650d39d92fc6172989a9cf0e61ca877f4ed14124d0aef34c764" },
                { "br", "c53a251c419616aab3e81dcec872fe70302a42b9a082dd6e848011173ef7c0d0a26bdc69021dbdbd29513d9cefb9b67cdf42dc8842dd7dd68da5799677126a6d" },
                { "bs", "a1a1f8d10e6f3bf96ab4cb7b15cfdbb281425f8cee5cd41587bf94124f0e2d12b20a6b055782076142c3302b0fe42ce3a56d4b8fa4d12468105f3a30434f2530" },
                { "ca", "b5ab5ccff1910db9d7dec8971b85e7fdba76a0ef458eadd3def77305a420c242e756bc6b5f331fbe237412bf6bd2d38ea7d3fc1e8cf568436baf6cf28a7072a2" },
                { "cak", "8e8820b1c4e9779cf7ea2c7ec64c572a4d2530f8aeb4aff7f5d905c05bfc717a1d8c3ee7405fe491742d2948e108c2287ff0faa4411b2bc8f63e120c038c27a9" },
                { "cs", "0505683435c782b407264d2aeaf6848cd5153f529c292e9ff0adccd8a4267579913660229947753af3d41ac8882363c7ebc92bd334b81f6fd7c28f19278ff796" },
                { "cy", "cde19e78da04fda1dcfa568a924dbe8a8d383f153b7b3a4b537d5c94e44f811e7af4c8f1a42feaaa6bdf62eb1f6984c02f4b8e6cbc59626a5ca85b7c8cad7f9c" },
                { "da", "6fc6359fdf2e887708a7740be7b84079c8edd744247f5a39b56443b387d2c27f478a31431d8b85c956cb9479394ecc3473141c41763532cb7d1893835c75685b" },
                { "de", "2b3aa21272e5c576b6f5ca6b77fe65bbf948b7ecc4d8c290c1f48f80013105ab74d368ac713d53bbc8a2d97f4a912005470e8466ee2ceee14760f94ebc947be7" },
                { "dsb", "2dfce6cf26844fb7fb6a630bf9f6887c58c9bc24d77db78b220e9439196f4bd90808abe4efb5434b2c19962ff71dc365ec0fa8b613f6fde80f48642cd88d0bb7" },
                { "el", "6daa597be91270f30720e08dde8f93e4a07243f400b013f6a3e57c14578b82a79565959aba1a53453dae2a199b126b4e76f5e7230c313a7dfea25f538256ca47" },
                { "en-CA", "289a91a90dc6eb92e060d1138ca45f659ead3caba0d3135ba0c98e7a8f66e19dc4e5802772e73ca84a8091d270bfc3d6d8866cd420e1020c9159d95c2290e738" },
                { "en-GB", "ff7c0328d6d85ae0b92d46f02c261d6e16064cc23420ee47ca3f13c4f9da13e8b7a590ab38a1291027131a60c412efd72bec37d3329d5c43aa985bc15a185ada" },
                { "en-US", "ff1b554a728e0a9d41f62f7c7a7ea0ca5ff89bec856aa07315d361fb2bfb190b6982c5e5c9a757db245c808abf2d2f44bcb1e5693536ff9d5f02f59d9d4c2a0d" },
                { "eo", "fe3cb796c5266de6dbd537f0dfff57ddaa1535a6afceb08fe9ea6f300995eb549692f3cc8ba1e58bc3a86138efa1bf5cc479d7eda07d2b666408c5569f697d9e" },
                { "es-AR", "fa080acb7942fcf3b79979070f67f7b7d1198286c6c829ed7fddcfafb827c5d2a692d07c3df625bc44ff1922a2333e346ef039d5da07e9da62ae750605d91056" },
                { "es-CL", "d3c0b427c73aa2d7d209baf8a01007e12b6b98c88ee94df4ee60fef0de55fb54bd57c3497f4f61d72ff85a9ed789fc738be929cd0081c2849e046d7b2028f7ba" },
                { "es-ES", "1713339d42bedfe558a5fbf3880fd4a839e281cb457fbd0acdfc48a356fe0c6e7b6554747f967e1f663e6cbad0ff89bd883265d3071018747a97d89a416a5426" },
                { "es-MX", "02366a6f7a630e90c23d574641d1eac5d98b14ffba8a7bd65065d59c0e4f3c74f0157191277c5226b526fdceb83a6bb91c0399b28e2b7ce45cba7adacf9699a9" },
                { "et", "c63247454ed3b46a21174399b9791c33f31bbb94dd7cc07c7599b68934274f3cf6e0a9ef8a4e05f75d7281337714a2841ef9368822fb2af9d2df0d903f73568f" },
                { "eu", "c6ebfbea708157d5c2d974010a3008f02f65654ecc059587c51d5592472d4283420ba165639d84e352103a6df2d3e39086ae0cdb0f58ed7a18fba2e275379380" },
                { "fa", "a945f38d3f9b108ceec6efc33c554d026d592cc1fae09706599068cd068445fd77c424c0ec702d6731e8f8ad2c75e1e24bd7d967e2ab2f31ad149149de006481" },
                { "ff", "4c8323a51ce85dcc7fe62dd422a5ea2f32e1e07b7762a72ead822c0fb493cc3b3d698e12ade6ee3aa08bdf6b9f62ef3ef335ad8eb1d2b60a3755305e69b14164" },
                { "fi", "9c2dd07e6c94383bcf7f9439774ee842702174e6cbeca075be3f4caaa65df98f92455d5788aa8e145e8f9123707d00ffd6525ddf032485535e8407f99fd85ee5" },
                { "fr", "359e944bc70cc4e38a9a9a2877bc08c8a3537e420035f90e75757f47641b89af853deef4a15f04ca1ac79c4b87cde50d6993c28086705271419ee107460ea36c" },
                { "fy-NL", "95e6282478a1335752c0766721f355085f38cf78f90fbba4901979ead63763b7f216742542f1c1f5763cf39ee61f5a9d855edc82c7ce63e11b7c10c7d589124c" },
                { "ga-IE", "fbdd16081f5549015ef247cdd50d3d2d4fe0941c76df020bf039584b81535f19100ca7a5a7b4686f4c75d18641e88216ce652295794bb29c5c2e527bfffc2da6" },
                { "gd", "4c3482cc51e398bea2d621233e05797e984543bdbfc5b5dfa04928edf1af897e72d19e428e60c7762c677a04b970b4f0e65da588ab1a661819fc83404c4619f1" },
                { "gl", "20d9f1a1b53c87fbaef0fd1e2edf372305ee6e83882d43decb26e806d9df9a9a144eeeb498c39696ca266f21b1feb6e8cc8ef5b11ad8eb538da1c8fd82a5e8ef" },
                { "gn", "9f7172694a1f709dfff21a052799d1f262edba0ca77e6f348811287c21d92fd364dc1b394628d774dc88fcc955343571f8f1e5bbf8029c21812bef58724e5d27" },
                { "gu-IN", "3ef4d087595e43f8c5facb9b3fc350793b32f1942f131f37f7d1f4f0511cb9fd4d0d4820528f986b6ade8c3160f68c03d3fcf3398b3b31b61d68ae913181c0e9" },
                { "he", "c71801e64a7918534ee9e6d0a72e79be2773eb5d2c44d250f87fe14d91370f516a671a994ea15a0f11fef35e272e85043758c2cc51734480daa54c1fea0197ed" },
                { "hi-IN", "0ff83274e786806e4666b0811cc72a6b74bac8095fe4d253296c2fd755e67893a1b1bc54ca58e4ea7a88b44829574611a86cdf31da7ed8229eb0980feb885b28" },
                { "hr", "5039e05eed6fd5567f5783ffda05368f0f184830c3d1f9dee78ab9f79f78fc5ba5764e4627e81434e04f6c06e6caf3ba95d5663406410a2f0a2e7c89a2d6a946" },
                { "hsb", "2ba7f3cfaff61c9637e081193d0dc88ebec278e7fbabe225397e8c189f3b88759088ff76c66d35fac8915db29ab238277407c04d26074f95e792a343bff1fcc9" },
                { "hu", "7d5e9f7ce66df61943836658cece91d5629661175691beda54b2f74d373fa6a6369efe097c292836841417bbbfd43bdbf0ca60aab7900cad236e4637fe193e3f" },
                { "hy-AM", "d2b4b0c06b4f254b1d06b378002249f5d2924738f3232c40dd4360074403965e0205f369ea7f2b65f2417be4f8655815d0ef254cf48cf4f1d0cf88637b8887e6" },
                { "ia", "7e8372ca3c7de9184ae121248998755001d40d5ada8977637776abb36544ca0eb5e2aa19017193ef0dbc72badd5443615f22f63fece91450869638391d4e390c" },
                { "id", "ddcda9e87216fb8b7d23b454719c128578f8188ee5c2aae02f620858faae3586e2f226179ab660d55c517c2a518b28f9871be4816dcec1c4984f88010dda3a68" },
                { "is", "6c02beb0430520c1814a0a86ccc924523e1a234ddc6a911d39f1e1216a49351879027ed30163c1278303703002bff7579e771e1114ef583899f9acbda99b037b" },
                { "it", "4caa1a290231c4527ab905bb421ba7acfedf16cb3a1d40c42024a43bd82ec1c1c7bcb578a258027bd0bbe55aaca87d847966729ec246f2d2546bdffd75474a10" },
                { "ja", "13dc20714ed26de6b46941c3b8859efc9fcea8c786b1e31a5d569f8496ed2024f171a6f36b5600fc01cbcb30124c6ad69092fe2511614d4829cbe3af43dca512" },
                { "ka", "0e65c1c62386dee019b7abddf200cc40420a77dcc6b1498a6a3d029b89a5130ad16e9980f326eca4c6d7543c59d75860e7da3c7f07e88ae5d3fa3b5bd9d793f9" },
                { "kab", "992dc6f10daaf8cb12db8cb425dcb881ddf7f69a2afbe495926dc94b4709a99fcee1224df10da0018e2e98ca67c4c3cd8f4017ae76a73e21d1f5e573eff1caa9" },
                { "kk", "b395501ebed6faff6c888f9578fb3735de32b6c2254e9110104665597c98afe1c7d99143fe326aa319bb6782677ebe68893e62b15e03d4497ed6ba5f8114ce2a" },
                { "km", "acea8a0256624c066e599ccf121ad6f012be6a778ea612a9f055c52006f76a41d3651ff9adaf90fa37b593031c59ebef8c695e9964e8187f63e8430cd09c148d" },
                { "kn", "125bb9efba0d4e4e9d97370a85103af5f48dee347331349e447f2809a9bd8ee2365e344fae6dd472e47ef72bfe9decad7590377d4f8baae01982341335503401" },
                { "ko", "68e7fb280e37efa751f05c649f8ea32dd5c9b87235bbe1d7e117e085494f9cdd5a18106b4bf777abc8cb8d2fdf0cd763e7d355c9311268f3368c708354cf7d3f" },
                { "lij", "65bbda7e3dbb44a3122475abc11fba89f054185cd021c17d1affdab0adae420be688c37e903dcfab1bbcbfc578dbb398b52a07e1ede2196d97df7a32bb2e1d2d" },
                { "lt", "0e51acaf8aef25f974acb0bfe763e37246008e4c9dba59cac733166e7a750475215eb1e129f9c03640be91d734687e35fba0d746fc9f25d761ff581e81e8de5a" },
                { "lv", "49b21d26033f30d04e7ccfc5ef39fa8d166e56c41233f06a68ed90ac4aed01eec13d3fec385b16f0b3ad404cfbb10b3d0be0de6bcfdeb5554120f05a3568c1d5" },
                { "mk", "bf0873e3ac70772ba65e5c3db5476c54b82a950d29683281111c82131d5cc6a85a8aeba94336ccaa2258a9428204e0e3e0b1c87be51355612d78cd8b19228e40" },
                { "mr", "c014c630186896fc308d0cf18929409c8b66dcd76ffd8cd05cfff3410c80b2d9eb575a955b847adb74a07f9e9dace85397824aa6b654a1ffaa81fe3308d6dfbc" },
                { "ms", "97ca47228b97c517dc025bd8ecf3144b84e1a4b3a3fec4efb3c536c34c4990d8d3c3a0f7ea620bbbf08e85d357af7b074b2a27fd8365ca8ac46de11b271dbe5d" },
                { "my", "42ccff34a99ae5966153e795442f2fc75d0648243bf044fb229e8827cff982faa49ec0817926e83300da07fbe5f4f62f9c5ac04f15c1bb57b26b7a37233c06bd" },
                { "nb-NO", "dc5799dfcb0810d5368f3aa98317dcfcecd6316570d030aab55f0b480707fd6017421ab8b23a393b55ac7eee6536c949000cdfa003428739e51fe58b9f40834b" },
                { "ne-NP", "c536e1d2963d1c7a62c07404e9d1cfbf1546cc651cb765a425ba08ed1a9c22951255cd3c33d68bccc996d559bac8d6f5ba3d1e31c19ee71e068ffe40221db104" },
                { "nl", "a2a4238210b927adf6c88ed3ee116fdb884d8d2787c301d21c8f95cdaf810f1132bddee50cdf74c669638cf50aff8d4a15c95b55025ef9ff018d6776ad7e29ef" },
                { "nn-NO", "6a51697c47e4eb6ea61920690ebc4dd2a3e88dfd2d6496e761a02bd50b107fd64097e1ac2c48be0fa402de0e1a7ad6d99f89aa8eeeace41fce85ae09ad3c1cc4" },
                { "oc", "c6b2ba5d824c5e9c84a55946a0b3bd93ab0e0501dab04f8d191652c5782d573787eecd660984927383196781b71b7929f3bfa00023e559693459813bbdde855a" },
                { "pa-IN", "de94f94eea4f8569adf3d6cafece5160f6a6974b8d17e43b155b245fa8f920865f52efcc33758d8feb236bd275e8114be446178e665d45264349b0b2264bb2de" },
                { "pl", "4b7ce7357adcc4925906ebe0176fb325b8b46c4076ad5a33b68e7028239c1bda2f05a4e8b896c3bebc264a10b96de79490a1820f5923c141c0b6ae6a2d194b77" },
                { "pt-BR", "a19d234c12071ed434c71d319623b279ce8f1cee3d5f6d28a725858fc5318512747ac4d594965151f447beafeb95abb3b77a14f7ffc9c8000bdd80ab0de887f2" },
                { "pt-PT", "aa3a2f9b0e6fa5d0020ae1ee35863d1467dfcaa5eb8caaf9ab23a4dafd4d2b18da5e11b0af0d31bbdddc4483e4467d2ebd68275cba4eb6c508a5718d340e3e58" },
                { "rm", "49a24433a98aceffd0651f690fae785a2c6ccc6c247c6dcbb374e4422b64eb379f6bf34dd854a5688befcd66326bb2e3c3c2a92116a82016caf3e5e8ddfc548c" },
                { "ro", "276c5aedcac8b9d5f3996a8c71608ddbed2767bc341d01405808d5a765284e9b834e4833f7ef4024a64946c876f73d3a41d29a53a2e8c83ceb2ec5be833899ca" },
                { "ru", "9dd3e6294bae6537a01b7fe63811e56002f4be0c47642e90ea0c7a0d487d1cb247eacbe1107393e354ee680e0fbf8d8e5708ab68ec1171b9df4cb3f4e128dfaa" },
                { "sco", "9c2defaeca40c7f26a7881e608f97934bca2b206223e9eb71fdc845e3284744380fc10d531f6a887a8deb52da82a2fe5ac92fa72b39ab456d98d214de0392569" },
                { "si", "c92440edb13922fe58eb117d849f1b05cd5be9a9991e1242ebb302b7194ecb5b84f1eae038a05ecdf9f61532585461ebfe8a700860a7ec922896e04c2c12bf89" },
                { "sk", "14d47a39374c076cf1456e5ebdb0f68920a6a41bdd210194baa64c40b6b563377a1f7961bc5d58685f738fb4140b9f1108b8ec870fbb4bfb7239f209841b3dbb" },
                { "sl", "0eb66b0a8903382759f629d13c04f6e4a8c4e900c0060859744e7575e80d607092d112d9291f717b937ea39fb4422865c3d6dbbddd9be8e7d7a970757d05c5e1" },
                { "son", "b6c5234628570e7c9d98d273ae02de547d1f8c20ec07dbeb3194a1a25084f9a0257951cfde3b257ff619ce9ac41f29f72a4f523870f3586c6d9c16f8549a280e" },
                { "sq", "9cd3dd308f1d7a52d2d30800f7adebd622f35bdad477c92c1a2260b9e929255d04b7e4bb40ff175214325fa3f19566ce9ec3283137c3040327b05e1af129645d" },
                { "sr", "dcc9b55e6c1c8f82e8790acb0b99f5c70e71f1a6abbe5b90be6a79b7e560ed76262d4baa1e485829bf3725bcaa0de49dbbc6c9f3a75e72237d45fbeef88d3dc1" },
                { "sv-SE", "1b5a61cc825b144a037fa21f547cd0953c797d3b9f8997b985c2affdf472bd4e3522e841d223077015b9417e17676b743b2f1edcfde67185453b62fbc93e41db" },
                { "szl", "35ab0e14d5a946a4b5ae5c5914d2bbd6b615238d747e8d2f336e4425320ffbc5c1239b17bf138934ec937f186a6bdcdf06a53aac5575c3b7d54df85dce7a1767" },
                { "ta", "d8000f7ba0ef71dba0d627ae547c8d724aa7d84da55ea445d0843220390dad864f7f98bbc239c41b67d3c0b56d9a7ef1ee7a180950d95ef013b4c14eee347dd1" },
                { "te", "a3a9059ca40aa5e8e557bb818f0daa886d9b4c5e07344f15548137f7d14fee243a6295e742c71074f985abccf5767374c8da8dbd2576c8b84d02548fbe2ace79" },
                { "th", "3fde960c879b2dd0543a78496b7a958c323a88b933c552a8d2fb90c8cd36d500914d892d07ffabf171acf021136fd4eb385505d098aa36f69915ca9f251fd104" },
                { "tl", "e506f90c39696491b510813d1741bb33a652cdde51fd254a2d682233f8ca3b8cbe6c6e860cd3667b17db45cb021b8323733fef0fa53e14fbd8ef1f67a8f5e118" },
                { "tr", "5c7c5579e196e29649ec7fe63ded2e5ef45ab58dca53f28fafb0ec42e3cbfa5e5acee24f8b95796a91a9819c07dac3407905c14d1bbd4308a147a07728906fb1" },
                { "trs", "cc04c03520138f8dedff67b0a5ce3b816e3a275c7c1053692d1a8f3211599772cbad2669d3aa900514df4567f13181f1f517a549a8f4fb2bea9b9fa2bbec04a8" },
                { "uk", "6f51c8f58a4cbcb5e53dfb3533d184653ec637942e458627512eec492a2e31d4b89d511a50c2771f9d448ed3595988a3f86b681490a8ab8fe41fa6c84a6387fd" },
                { "ur", "d9f837fa96d1d22c17073ceed20993413708b6530b4b22f659d023646529c34ed73d55420512ce1f9343ce859962bc6e419365060c6dc3b06255e722a7ed7916" },
                { "uz", "c1bd7589e31a1af93681482e581dca6b94693d13bc7fbc509d733ea1c1e1de089a6766a59fbb71ce7d08ad1414d26deae78e216458cf524a13f4080ce90cdad4" },
                { "vi", "b851763a53afc03b454358f8344e9597572eb7238e78a5947376849193c43414b2e80669be2bc47656409d95fc48024de51a62280ad90ef39bc65d4bb5925503" },
                { "xh", "26561c1245d7c12fbd9eda8b740f57e5a09316e98b8cc549f12a4694bacb3d187ccfbed344c508973c408bad44a882fb47b7808dbeea491b8ce566378366b84c" },
                { "zh-CN", "d982bc1d773c4736a64541c9fa325af68d9d193a9ced1754ff948fa602e7d552e02eb09c21481a41e27bc8d588e5720491001863c8463fa51e614d6c632d96f0" },
                { "zh-TW", "8fe491671231b5f69aac8354c07ba0d11ed0f7f696a440667091eef0518c519d432a6e6da62fd7e3e23cf977190b74d20c1cc67c4757155723b073a09576ff2c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.5.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d93897cdf3a582683cf7c0f666471d9405326f7d410efa27cc2c941c1a78c5ccdbfe739d0476034adb202f90aad34c3389e2e032ae5f34885d02e1df3b89dcbd" },
                { "af", "7dd0b7a1c586809d15c54925298334e666606efb87079eb1378accf81cbed86e22a54e82373798d19a5ee8e2a4d8f8af604f9ae824062497a237eada99339510" },
                { "an", "ff21eb0e7e1b3d92a4264fd5f2085efa67ebb52d45f67c1577584a6a34411bde3fe19d19ebeef9f0c8276cebe8da60c52bd2514d435c7460c3ebf3497e32d588" },
                { "ar", "fd5ce3b58dc7fdccd1cdbf64cedaf415e4eb2be4c6ddb349aa1f23f864de456da42b5821e7e068dde25e0d3753f58cd9497859f7fa11485f2657232aebed09cb" },
                { "ast", "d4711503792b3f397b821577894fe0790b05c6bfadd22422df5b2f5dea275739702d8160add7cf1ceb9787cd1ad22448345e0a38cbdcf9e1a377b9d5fb867b1e" },
                { "az", "4f963cf1899b5805685daf8d8f3fdfbf39577a99b5097e59fd43c5e89290d36c8f5f67cbb90d24fb50805a2fcc9214a5bc79e92e2ed3569a09a34aa9f9ea7828" },
                { "be", "c9b3af051cfa4c73242709ab6c6be5ece48641219e7ca9970c05f44e47c1af503daf44a6e689bca41e254aacc9b7242677f7feb204ce5edd823b2e26f5d9bdfe" },
                { "bg", "b89fdeffdbb3cd3adf0e2b2c970d28c2d5ba4c935c09b2b84a109f28b0c9b6259d4b27a9ef68be2fe6887349d4e0a18c3006bcba47d36ccd7f2828123aa21c47" },
                { "bn", "09e54c90c52494f99e074c350d86820572335665a49d5382b512f455ae180b8a0725cd0809e9c814560e0051fef62febe3a8a665f6e7d091101967bd7cd3ee0c" },
                { "br", "0a88148f7628449d718838fa7dc0645ce977f0dea858a81f59715100c9e5dc847f1985f943ee9327d22c18e8eb09b0d7d159ad0e68f065c92bea78c975929d2e" },
                { "bs", "684d41838914b89ce361a642158efbee34eeb0544520e89c71834e42232b6229393bf4e526724c494c45bafce8a3fcaf5ca48845bb1f140a324394b3435fe706" },
                { "ca", "ae1732e94900330955b91604070f90d42e389460bb12dded687c8621012c216d3d2519c2b80b02bd19f629ac67345f09a9cc8928cbb25446f76e77f3be8edfb9" },
                { "cak", "97320e7bd67f82295727159b53b1cb71032903f0b28d7c329527c2a1e8f625f37e99047ac45149e5efead93da30c39778ec23b7b7eb42b6af1533a8dd96ae6b2" },
                { "cs", "36868ba9dafb181b2e49634fb7130ccefac9eac0c5b2eecb6ff7112d528a5d8e98b3c59e5b50c9926e4b4e4542ebadf70f8e908aa2355e7ceb6f2658c5a86701" },
                { "cy", "0039a787bbe18c8389f7ae52a5515032114f91d2b7726210fccfeb03039c8a7494867a7305fdc40b5d75e0f7367f141563acab508812eac7f392ccb05c4236db" },
                { "da", "6f45780b650c1bb9e0ff165b41f1a66d3d98e2d6f34796818521879fa217008882deb5b8c0b1bafab50abfaaaa0f8e4e8fdefaec48585aded68948fa88cb27dc" },
                { "de", "f533d85cc77b560f910bd1ace7e8fe4fd3e225b5aebb067f4dde16f2fb6534345a0ca0810cacb554ee591d9d2396a927de1d1e3936a122f7c8f111016c09ed89" },
                { "dsb", "c287cb1ddb619901d6f821e8cf7f89993b59f75de8a89d1ffab6b816453eca3f04583d3299652a73abad4aa7eeabaa8c6009493bc69001debecb449f6bd29c4d" },
                { "el", "5d371a16ac28aff8a7cce61169979f0fcfa3c25a59780b1039f47ebedcd6bed2ad738f6d43ad8afab2b21444df19f2b7c3e2ee4d28abf2ad4dd29d1533367b36" },
                { "en-CA", "b6ce189a20a62c1b87686f5fb6be3d2a2afe452fcd469bfe6f3fb01e5355de5bbb8dbe0224a965cf3d0b0822efccf7a385986cf9c614985759ba12940227b6a7" },
                { "en-GB", "5ac8a8d7a73cdc5d4736c9a125da358e242c46d68af92a8f63adb179cb83ab4805d5003cf012cefd5b3349b0c8775608dde7422be30f21b8d37254f551712f92" },
                { "en-US", "8a35b718c26234caad1a0be055417b4bd1861cfb4091d10f4c4bf0fe59f1923128c281249212f5a827549b1fa4c4364b5299f2888a75d80e77216e7f2936debb" },
                { "eo", "10b0f3421e251c3ffa114b8ef4b826d1a6a6b1f13fecb0daadf957a832e95b0bdb8ac46571d5d727e1081d0229dbf87136abeba542a0b586743cf2de56b8b002" },
                { "es-AR", "0ee546a7ba424523605afe86cfd88905ca968d94d8614d29c9a382411b05f6290646edd23ed50e067dd3db7ba364672b649eae0e641aeff17cc06ca1a1260978" },
                { "es-CL", "f91c1c3c16da02a3da4e77871c49138da09097f304d55d54700dca7a145377377f10491dbadb58f5361905a56687b2d1628c04f3ab2508e4972cfb331bb94d77" },
                { "es-ES", "0eafec2521bd5b3771b8f9d3e5430f3e25fec23af2b4ca6986fea728a2e4762c2e0fabdc67a1c4a769a657057f9442f287c4b014ab4b485f5192c0f2c20a7dd0" },
                { "es-MX", "eac67d195c052e2841132d77693bf5e7b4b47593da32ec14e12be7c4b6eda88069f9bebcbc7e8630bab42f60d6a37335c6a18a715bbeb359f6333196b62a7157" },
                { "et", "eb4f36207d6eacdfb15cc963dc0ea85f928aadf7212eece3f27cd10cb1e5535c16a29323c2cb03e0108307d4e9a5900bce9d1dc51da8bb9f585e48295f4c0332" },
                { "eu", "9730a3f197e90eab954846dcce1ecb7778473d81d4814c39722edb7db4dd3e01a2c5cfa7b5faa5b9d3e2612c25dfe193a8cb881f98dba2f8fdf6abdd3eb0a206" },
                { "fa", "600e3355188c42712c606081fb6b45cf32f1f2278aa195b6eeb538ab624eda1a77e9ba3d40ef45978d197cec498949205a0c0df81f27d65b2f4d7c5917851e91" },
                { "ff", "a797823466ee6bbb8ff89eff5bad992f4335a7f463997d53ad4b9698db49cc2a1d46e9c0c1565ffbb37913110adf0b86430b29c65351cc042820bccc02d7891b" },
                { "fi", "52804ded4e01db0746be8c83d786a1cf56a6f3baf512e9dec91f78be4c319d18980b45d1fde954e3a97562fddd3cd9869df680b5c8002277dd64440978921154" },
                { "fr", "8f26d6519b955770c1ec56a6bcb25ae1ed5889f58724f8d7c5eb0f325893d4c59e1cb2e40098aa36e1e6bc99a28d9777a34817b653ae4d5ca8f2f7a8553faf2e" },
                { "fy-NL", "19072a288b56e8167985a2a4f74276512e46d45b36416989a9ce2d9d53814fb4c23d46dacc1fdcc5f2e69bddfbf4ddf80bc75d8f261cf7383d1a7ed6a2f2f3a1" },
                { "ga-IE", "fca511101b0936ece78e4d0235b14c3f314b473f7d424529d0352ca34bd4966b1b534201b9b049c409b1150904f2b512fc7ea16f17c0db5644af6fdd497151e4" },
                { "gd", "c931c191bf7e5ba35ea09de26e63e8b47c214ea8fb123bbfb6ae6105705b028f5a7a69bbf4de86dde6a572bbb72d05b9fb8d37de3b2b1e4017bc480e21cb7e67" },
                { "gl", "db11b311c0685f26b5aeed8028ed83c56ddf0daf7bba6b8fbe1dcb2ab10f9eac6c6422c7c14af81e76dd43961192df73ad072c21ca8314a6b6e1f35f1b00ed05" },
                { "gn", "aef60dab162329546c17b2b77bea815f2fa7cd217d2b0a56db777de6d7c64ee77b41dbd119c1509a2beff01887b319a7e73462f0eb2c997a8e6809a8d5598646" },
                { "gu-IN", "55d9afdc4ad2ec6808ad711b3dc18825d55d0746dcfce94b03e632c185590912d7da04036853ea6641390ac2d2df2c246424181b0c037bf7fa4120a94d56b0d8" },
                { "he", "3bcb4ad64b45b08c554b7508ee8ae650ceb4b9798908ebe75f8ff80e8eb4e7d4166351a897182ece33b58facdfcc7b847d63d052b428d37ebfc46356c5f65a1b" },
                { "hi-IN", "c46f67fc17630860071a3ea246de5500da9ddfc18d245c229b7cfc8fbec69c917bb5afee01dd1439c58ca1acfde12bcc24187da65495cc898a24139ee0f1a617" },
                { "hr", "aba21f785604db7c6b2eb3c720da4898c7c8e4d480db29dc26d5c8a7876fd17a5d4e892531612b907ee95037e6c00ecb4cbd86cf84dabb2bd57fa33c5e448455" },
                { "hsb", "a88a27408ee60166954eccf0ffd413d16fe60f61d205b297cc3ab776f8ea75c8eae7a7fabb7f5a6332a0aa0f7ddfa12bebbf5c912a751d5aa8a73784c9c26488" },
                { "hu", "6909c8922207109a9988b535c67679986f8c016423718805a6b3e2e808982432d109f53cd67ef4de6d1169d125334db7260079012ddaae5331adfe4776415fc1" },
                { "hy-AM", "22d2400150b26f35b24a8e318e072784e559a2d3bf4ab99355558b10dbd4c81284ee5d201c6a1238ab780f69d9c14d4d6f9a8bbc2bfd9166988deae43c78917c" },
                { "ia", "61fa1242bec7254034dd0d7bfa8282ee47e85a4f31dddfe5e0e78951a3841880fa158feca06919813cdd767ad1f50440c7eaf1bf67461b48c051447512c1b9a0" },
                { "id", "dd3cbdb0469ab4d4adfa70f9658fedc6d588b3a7c6d6d5e6654de0f9c24a8d1c0b32e3a188ca6bc1d1f3eb9bfad955eb454481b1c3673a342cf460c67706dd72" },
                { "is", "c696b5d746853dac4536bc3109435fa6ffa11b90834d0592385f81ed509ac382d6eeb85a7b15df8ff9a2e89f92a0cb7203e037162ea276cd67cd4715216ba376" },
                { "it", "7a3d0117272509b0e69162a05452ce06b3a33659cd76af05c1a76948ff0de7d837ccfb134eb32a29bb12022645acc7b3195b0fdc786a263994c537716b3ce8c7" },
                { "ja", "02b901b690d9be26d4ef7e1a2d384e219dc16c545888fd0e4f1c95db5f87ebfe60cac44d7723c095419e55d3f264f4b722647e71bf58135d45381d8b322d3c41" },
                { "ka", "61237ed4eecc2f75e05b2ad3fdf3d255edb636329672bfbf0051021b91e0c47acab331983716f9490b82ea4751e925d40babe6c0c9ecad96af0cfb7c5be80f92" },
                { "kab", "7fe7de49da2c01267dff4a186a68e21c9a8c2b8623a6596e8a48a9ec703dc26c814cb9b9db46ef15cc09de26e78cbdd86794c1c9bcd2ef052e6d62aed520b449" },
                { "kk", "5cc549b805affee002839aa8e04a2d61708a9615f378201664e41156e445ef1ce53c64d05c2b91b6c0288413a71bb4832c6c41151921b9f82a4c3628396ee437" },
                { "km", "06e3973677725a2cc7387246cb2a56504e38def8de51b686d8bbe25a6fac72f065d981384934528a77cf7db069f93685b070a088710c6eba71b3c9a13aa961f3" },
                { "kn", "e9259d58ef63a851c6e83292f85c86a9b11c76ece567588af6406551edb6e9384571e595ef9c86b3095ea4f5661a8a3dddfc915e2126562aece820315ea8a648" },
                { "ko", "a01950fec4276f8a140796a7d36f15519496b1c89e7753a4c6b222889d0dc3b204e53ed1c74ac38fab1644e2256ffa628055e22a6b9a55dc27c5a74a12378018" },
                { "lij", "7d4acc44f140e1c877fd75bdc385351a0f3910e3b46dc5d8538ffc9e7c7b1a2356f6ec5f2f19cc5bfb156f54402351a63c68551015f0bcacceb62b72f6deebda" },
                { "lt", "49cec3ecadf7780d74f0ede468680f6b4417bb67214698e26b79eac6213408fbb5061428fda3a379c0c18f697d0c243548b639b6775f34a31a98639845ef87d9" },
                { "lv", "de94b651c5b82e0866a8b90478d4f35ec3fe6f9be46dce5ae5aa7e52115242f7faba1f91139372df7e1402710a5fa661f24e8fe817ac54bb28dcce3f05b8d866" },
                { "mk", "df09da3463a3722ac59eae51adf9183b52e38e3cfd3be22992335f0440b8c8aecf94c612fc60fe832650dcba1e0b47564045a40eb9d933845ec088094c7e7efd" },
                { "mr", "27c9ae7e99f7e0d86804fb5f0d7493ee2379a432a64ba88f176c6aa899db241554aea0eaea1a9f5a0ca757160131948e74235b2717675f414279fe3332b1f588" },
                { "ms", "f8daaf3f440334f1bfdb3d43fbdcb9e2a306418b05053a673c0df7ac3dafaf3db505f8d4552b23e6313cdd7bc2eed5fb8be720f21136f54093c063c1ed2e4210" },
                { "my", "97cfdbfae34101394331e8c2972148f5ee964eb9d655942725ffd1418174bf080db61250703a7f3644d4781ac90cd6087df51eebc07a5d6b464968bb06166e83" },
                { "nb-NO", "ee00bfad6ac27ad5c9b5ece4fbd5bbf9942378523475c0af93209355aa97cbcb6b6c626d7f86c1214563172a38044a4ceb535562e8d3914dfdfbc7b33f441196" },
                { "ne-NP", "fd3707a6d604253dfac3b261c2d7767636242208b87b81a52d2d89a64393eeb4d168db020fcbed77cdfad2aa1aaf311244e99c0226fc1f7c8cc0f5ecbba29f57" },
                { "nl", "c15039f0be35ba52dca2c87a97f54e88d0b73bbdd46a2ba15f958ca64da6cd0ddf99748ea68ac011176d34a27ab50dc4b9c3694c9c86164e998dc4e30b63e48f" },
                { "nn-NO", "6bcde2348c709cb1904bfb52b1029bb9e37ffd0340db79bac1b8f67821c13ec0e87dfa29f99e11d1d429f4225f3aa70b3b7cef73bad24980c31a2fe25fd8e23c" },
                { "oc", "768075155d3818264ea56537dfc7e2a5bc557f9925ca7df1a1a730e08ead5b7582c2d8a55077e77184b186984fd9cd0742c7a72c2a878bf008d68a86426c44c6" },
                { "pa-IN", "62c403104ba67d97506465457a2e3202c843c59564709bfb3a27046ee8ec352339c621d605552f46ac3f1d3e6c4f925450bf6535896b25ff5905194a6859ddee" },
                { "pl", "234fb22470b012bae23b5fdbcf4bf936a8ec59ab0ca3b3ff806a5560c0c2e9a76cf3d390e6cb97aa525dbad8d2d7b3d79c2090128a224715bb468885ad12adee" },
                { "pt-BR", "4ac6f904855df3b1d9921851b486cf9625bb71c259cf2e49fbc55f8ae4e3b16eeaa91f3075df3379c4c6238b061aa6ed0c5a8f9768cd044367e751704ed1caa5" },
                { "pt-PT", "ab0224feba205985cddb9e4735c2cfbc8bf9a5954a921d880df849aff4cfaa1e1e34716520ab913b4513a88a4b87d8eddc77cec59abefad4e65da6af04f747aa" },
                { "rm", "0c1bacfd22a90df5bfd0717693a65d7439ac0aed438b5d8dd43acf2b0c5313c6f5f0dd8a55cf56dca64caa0ffa2edfe5dd58490809235339690bae1875fdba8c" },
                { "ro", "67f4d85afe32bb9d1322ed0298df3a974f42dc7c0e88667ad9c569355733afea5a9931e36dec46770c1a994ea1cff80381cc6672f2cdcb403f4e11cb73abbbe6" },
                { "ru", "5a5bd234c937aeb7ffb3799328178ecb7dc2dfdee1d82dc1cb7017084ca17fd2733a1ccee7e31eb553a7e8bccb77f5229fed7698d76560e06e09f5fee8e9380f" },
                { "sco", "638896b11dc42dd244ef78050511a3a9b457a9fa5647f86fe471c9ddb8ad22bfa62a7f1a0f23d63ad74b0aec37911baf18ac78f4a3532178665cc0f4cdea893e" },
                { "si", "2d6650d983a985dc4df6612b14cb649b82ae72dc2fe1ff3176c4a69722dabac676b30a6db6bedb0b37c975fc07c486c95384ee55166a686b00a5bfc75130814e" },
                { "sk", "d13d567d1e9266bb414530d31e53ade35fb0d59f5e92b518b26449bda60ff2603454414a8cba19d51e3124d53a9d39d22464312b5b244c864d2cdf9c4579c82e" },
                { "sl", "0911e427e24c5c00473ff771ecb489cdeebb02685b30af7a5b8b0567ed9512793a5a7cc68b898ff92af6b955d1648a79f57e604a90b2a08f58f83e73d94f0c41" },
                { "son", "13535cab9942f13c3ec97c7c9c82236de9a1b6d30945defc08072f22f05d0f07de17ff4fce82b75daab9871302bbc171a3c6e7c264f409edf398e8bbe503dca2" },
                { "sq", "40b761969b677534e931cd6e67ac0233bacb97a1c4ac4f6e9d8bfcdc79f73d7b76e9987d400d1863d4c4d2b2d5659091497d52a383d4e9ca682f5a1c0b8c5879" },
                { "sr", "7bfdcb89b780e71d4e2a720a7851a803dd2873d8c8f5f91ada4c9858a0806ceb77407f48c4dabf81bc6b59adc881dffffe2f6e4f3832335caf5d54c4408ba054" },
                { "sv-SE", "c20ed435d6145e666c7187170bb3e483635e8ca7f07a280106e42df060ae3eae09ddd70061dcb57e82aa2d7ac2846d2eef1db27963fd9b10c7d526fa929d3c48" },
                { "szl", "b4e09f54e0ff8677c3ea2386d3881a4684fafb66ee81b8287b9c2b70e1441f4dfa50dcd0863d4a4b8a334694bd9d79b6c5dc9004ff311d43859eb3455e2f785e" },
                { "ta", "a0878da6310e70b00caf38ee7e85435376227e3498f13574674ac2dede306081ecee01a0a9fa0e1f177fa6d5e35e1a35e571e360b1967713181c1601069fd5de" },
                { "te", "e3a8c080d2ee238a989385f11036218a7cfee83ba55380d7eaa719943913d7dba77a0f8437a9d867fce90baf46fc0684ddc527e91f28778aeec58137109efd88" },
                { "th", "df6e4156a1b72e9da30af5b10d5ddfb71692e7e466293193bf3fd6cf9cbb6610c47a4b38851e1efde9cefd714e63e6cb8f52438cca76683f5fa28234c67ac2b2" },
                { "tl", "8f679db6fc5f2923584afa5be707ddeac36f92c2b7b3dd282dc60cc301a21e42214d927923725082d942c8a1acc8eeeb49b16d591d3f08d0ecf64d59da2903f5" },
                { "tr", "fa9e32e583c6790a6ef6acfaf89cd2108118596207c1b4dc1e25c064255aa04e41aad2cb3273d4e59316965d8b0a1b6e8fd72810966a51155b6f2449daa0d750" },
                { "trs", "6800d83cac67406201ad9e791aff998709265c8901c25ea4206df7103d67757b50df364737e61a8ddb81da41ccb53275ac573c50f0061463cec20b1b73067e97" },
                { "uk", "f884d655ec52acd0caecc9bb083ed509b3650dc39ddd78ca76361605baf71f5ca2f50906b72cb878311db609e40a30d5299fc159e747e3f40f7420e08eaa183b" },
                { "ur", "828c246fe5b00d432362a66ce7b3555db921d4b42584be38c83635f6d693cb092f7f4d802e9808e0fa9b83bbb3af79e236ec43c9593cad70d074df0e690e004a" },
                { "uz", "3cb2e59346e422fe56576d8081f2b46b12bb47bdb5cb435e42b02471ec583275079b6b52a3cddac0cfa769a585a4d8108343cdf73074ba2ca7532d59195d8227" },
                { "vi", "ad85db756aea97c0e85e5e825e1ed68f5734185af55c7fb0097655d773f0da28dc5c98a00b72c8d8cd563606ceffec684b820c7b9f3fbe62d18e655a83b4253b" },
                { "xh", "3c59353fc27b96aceaf3a46a8479ef0fb52bbe0c724e067509b2bc66544b9f1b23da8fb4b7c9d15c5cb9a41e906ee9fe2a19aca34fa13eafcd227f0baedb905b" },
                { "zh-CN", "c675962542d3c343e93c23ed5f9d53cd135605b24077c2278398ddf467a5df2ac21212446d5714e5840c865597defa686ad03c1462b4623511af4c7726112d43" },
                { "zh-TW", "34d041b5542a1dea143c453d295c5e7e9ef0f060cf9ed05066ac1d0083aba174f117cf9c76f3a4ac4d4214c1424db1930ad338ef82ae351efa8611482bcd24e4" }
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
            const string knownVersion = "102.5.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
