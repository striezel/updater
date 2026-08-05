/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "721489a5acf05f20e2264eb28fc1e8d2dd466606b600feeca68453dd1a0c076003134a6555c333a49f462ef06bba1dac618ee3df875a893c1f8021f542aa2d6d" },
                { "af", "58991a8f16ace2330679fea9aa987c99d60b36e5abd64652245a554e3ed6c1fb20f7e7425c395a77398ca14658f855a07b80fafe9661a2dfa75cf928e13307c3" },
                { "an", "ab174d29a9b20922a9a23f3630a392d0af966220c31d6b6faa1553c6e146b21608b9248698e7d24fe84dfe4ade288fe4d81ad242904dbd65282aa6fb6c17e073" },
                { "ar", "8429b36dec759d111452ff411332e6df494cda1c94597aade9c5db2b29d6b11ddf83367cdce41757089c0c072ce8868ed74b1f4a58db7f4428ed1b00f06490fd" },
                { "ast", "35e397b0dc60f659e3b6a235ef372026e21d888a40ed5764e8899ad0225728886eb6d6dad6ceddd50914120b173b67b297eb3f132a58ae4c19d5dbe196ca29fd" },
                { "az", "074fb02ac9e833ed599323f97347603203e1128a4fb561b4b3a0162250a0a6da3f116407e179fb92f31c0861fc34c73777021cfdff3ba2b96494bbb38b1001b8" },
                { "be", "ea937652b1b0ec3ef86a7cfb5e106eec92bfb2d923435440857682913fb3a6f90473665c7589c6d8a876e7d8d16c3d0c6154b78d13dd798f3a43200dfa181488" },
                { "bg", "23533b66535e969ebbe66b08379def34fc0eccf36cfd645d611205d30214f871a76d791ee6d27c1bbb77e23398b048f34cd53b13b1dbf57baeb67b8d32a58add" },
                { "bn", "c454913ec81cddd4bf6568a795ab243145b4c320d51f97d0f8d709aebbe64b4b5979fc5bac3e042dd0811fde6aaa926af5eae5a8fea1074269cc84e7cbe61d7d" },
                { "br", "0823322b8875dacd01870cb3884c70e029fe1df5f9a09280cd13feac8e4d67b2770670fce0dd6184331e824618f1fbc498afda4961197383b9ab487f87711ccd" },
                { "bs", "58da2de3daa9654de722da5e4be756de0e2d03fef196657aedc2fc91627043141fca0beac8e5ada1eb21584866f8f0c4f4e035489cfea06e42b8372407a3502f" },
                { "ca", "ef3c63c5e4fc5160accdab67aad66331a32b3239ef38d9ced240de10e339fcfeb8188f2128ae0cd4d293e09155a8a417c6b06961c5f0bd1a36fb926350a19da5" },
                { "cak", "a99838eb309729deb1e9bbdb2ee6b0a7e1e6fbe0f1f1f9f30963a804b3cfd9cbe76837da2349a680b77aeb7493d8be4831054df2689fe996f38b868fc9e597e3" },
                { "cs", "2cecdb534d691a2fcde42fb8c0b09867e55bf66595b120fda12619de36d556e8779026a627655283065725eba324db77b0b6c61f5bdb24fbc65c10eff0cac917" },
                { "cy", "345f348b618c811a8d72201a29bde34bf6ff81173ca6945f6c99898aa30490c1b631ef9d95e3fa41d129908fd607bb718566eec31c9a7af6381b2d096ab8c751" },
                { "da", "7767f4d3c258a24927d71a94f228e7480143de997f63e22fafae3f881555b9e637f66c9514db64c84e990bb9540b4920f8e937335cfaa7c34473e9584c8e280a" },
                { "de", "de2893b11781864afdffd9af79070869620dc96fa66642851a1eddc36f391c72087c8d520cae989691dd29c99b6f3be727173cbce91aa406ecd395a91f047930" },
                { "dsb", "96ca000138b4ca8f54820aea2458fdbdbe501123637dd43d7a322bf7e207fe01ffac45e9ec33c631e95ec7efef1e9fa831011d3ebd8fbaf45bf63e1208bf8ec7" },
                { "el", "72f7b0f933ae7135ae356dc0e3c8707e6db4a74a145652c435e9fdcb90371e657e5be837d26b22f3bf6fb47b430cbacac4d89c5fc8e6f95f1ddef912a5affdf6" },
                { "en-CA", "3ed8c8553677320fcfaba6b0c133794fe5ff979e123a7f39c24aee91aeea9324f9208fcec8780acd98982a7ea57f5a4b5f6016344f28edb62b3f9e506f35b6e2" },
                { "en-GB", "4d02573ec01d1b64eb9cdc8dfcd0c4b98ff91ad62de48fa284b8caa7c1cc616c9e76f019c8d00215bb2436e17d7bc4ec1c5f50a328a0069e5d2c72162571b97b" },
                { "en-US", "1b104b2a1654db7b2e5f530755da40fc99e058273efb3b0466274306c1cce1da29b3dca1de511b4b5e879cdaee3de9b2ed0d8183c73b629831a5f7f8c3af912e" },
                { "eo", "698724a20a1e1f2bc1426aa806be5c58cafd8d43def97919b1583db28a62cc285b6f36d30346b821b49f794fb96caa375e2458f79e19d9411fab11b381fb9d30" },
                { "es-AR", "a803519be524904668d56a61f4531ec13e002146ed4beebe506a7d28d974319c0ccd8cfa26434a201e0fc1b16304111b836c1a0d8bc6fd4e65de4eb6d5f74d6e" },
                { "es-CL", "bfcee3803d80abe9fb9087d61c65a54b13619df5e2b0648f5db969950fc8921716e6d47c7ea7e68da2008bb0f1718bea3e7929adf7da6a608fbdda52bc89752e" },
                { "es-ES", "da649bd07aef95af8fdbf8694bce709f1f6dd88889597f092822bd0a6015bbcc097e31b61b3e388f39598879c85b8f22bb8aea20e9b1f934a0a867fba53a8f93" },
                { "es-MX", "fe48f311dcb434639bca966695ede323a68fed9a14819400566c5871b33251560149604272db6c45c00f9d502da8d07d9dfa08081c45a3345edc2a8703350271" },
                { "et", "07299c2142015574ea6be3e7e07693d95f9ee3dd44a64f7ddefce50b5360914a39c15646d3f9b89db2a799c72c024632572623c53b479d7d977fdf0b36e98770" },
                { "eu", "3d663366ae47276cce31ef876dc03e594a30ef0366c11c5be666c4753882e558b463cec56873048c4c62e76cb0b3e34a0fd9baf288106db948b85b465495e7e5" },
                { "fa", "75348f5b4eec40290d549dc0bf503b597d71d0436d3b6d7c41ec83c93815fdad6daed29a3a656ef9a5900f1b594b1c78c807ce5b579bb0379eabff5d072e6242" },
                { "ff", "e0d512360f8ce551faaf2ba4fc18998fab6f12cd3cf8b695b1fd1eaaa5ee650936a0fb7855928cb0e2eca92533d99ee160008c5bfb833c7279af2ea604a4e0f2" },
                { "fi", "fa9d4475a2f10c73366a63fad84d2994e08479bc5c0a91fa7ddde6c10cc5b526ffcc5f02b5f748ca3d06bd0845fa3029a9f9d5c965715055f5cf3602b71b4e55" },
                { "fr", "eaa2bddb302d290afdc3067efe3e6210fd3387286a9b16fa03940805c21dc066b6cd9385f7d25b8c88586f22b4491ab5605b333be3be575f5d78829f84b15e40" },
                { "fur", "7da6907064a10b7c895f775c7a5931cc4f5b937555f8d46c148c3e0c75b946321f70b4530b99faf88f1a3a8058bfa6db4f3693b5a3644f88f3a889b19917df4a" },
                { "fy-NL", "c945c018b271c08f3a12d56f7f41e0764d37f434b4b80d2381009280ed778b4e1be4d2faac000f41ba5df51909389f80c788f906e39128e1989e35cccd8d362b" },
                { "ga-IE", "c56039e9a7c9cc9e500a0fad95d874089d834108c6ca4a406eca812e0ce8f7afe1bc92a4e544f926fac87063505ff13383e1ea275ad2d3e436f5ed4281bf4f35" },
                { "gd", "57086297faf97de24c3014436a541681168e9e5bb9d06adb12ce0c3468a8795a35deb8e2a560979a70ef1785905681e9a838f56998939c52c6a66affe458e4c3" },
                { "gl", "3f5a260505f4f8a14f10a8a283fbf7a097152d01a07f3b7a02c8e8b6434c6d5bd4514481778a235e11f3f0a9ab17539d4e9dabcf3b76f2e67b091d3fcb68faea" },
                { "gn", "92c867940e9363db39c04cbc4edd94f937b41d773e8895f1b8c24fb2832c21e451cda6ba83b4cc2d35a45e7fdb8017fc2a257a4bfdedaacb26e9ed20599f729a" },
                { "gu-IN", "8eaef54d30e7da968b534b4c09f729a548cb6c5068a2bce913b8266389fd6504fd40a8fce663b207d9a0b73a43f74c41212c71d30f02af49358a2b12c1fd011c" },
                { "he", "ecd8a4ef2133d3f4a6df29ecf4d2dcc79f530b09fe9dea7760b2cce875e93aaceadfca1343e68b51238cf14e270dad1f883716f11d30cf98ff414e06629d6468" },
                { "hi-IN", "4b5ea8bae135277fc84d53daee69b19cab3a957743a4190babd06da4920a84ca7dc54aecdf308ee436b191dd49a7cd8f539fd9c1316c12c9184ece5144b37bd9" },
                { "hr", "c285bebf74e57947f52de73c8f6fe8fcb430c1b6d4e3f5f30b21ee6e3aa5be722299239af07d7d65f18c84849deb0d4e3cc5bc62354e0ab40e4f4c98f8cf5d8c" },
                { "hsb", "234ab07c209bd6a4a7c272e38a7d26b57344f395b214b6cabeb9c639f2363ea364a8f203f463b688a5b8403748044e5af9f52dff949c156f8b4708d3b359aa67" },
                { "hu", "9b0b0bf107f399a542a0b0dbd06a00e8bd95b9b35ff14518e6f6b11e9ae813eadb209879578738ecdbd4b25fda73f27b199a50c186263baaebb0ade57793f69f" },
                { "hy-AM", "6ea14d7360ed1f01dfd960eed5ac75934c697190aea6cbc5fae6f23d7f8642d5c64f26c1ffa7f981d6129ca3b8d78d50f850f42be52061ff894c2713c588dada" },
                { "ia", "20f71a2b43e5d04920710e306ce4c5445b13cb737fb6228b0db56fdcafba8833e426024acfbd201e58ac14fd5608499dfdc74bbbd9b8b1aa0833fc309dbd710e" },
                { "id", "23ead48b04c179c1b98bfbaad0c7b188cb128e080f331396d759fe5857fc03985e47d25780a931fd9b75f3cb3c053dae0a43cc0679944ddc367b3544d72f5ef9" },
                { "is", "0f9ab71bce1b6e91045626d41fad103e482509e5a1e06602614b5e2a356be7be2eca7e5695510d8aa74c76b4a7004358de616983e0b7e31b7fab274167e424a2" },
                { "it", "ab553c69b507b9462ba15c3c712e1f23045116fe3f2a22ba4f6cc9748f19128b05707d5dd6270586c598c10b232a1e778328f6e077bba7b88c35867919222c7d" },
                { "ja", "a1bb2ac5767a73671218fa6c921c582aad134a1fdce53bd7aea5ce8d2785905f91dff9eda5522b6aa1721b7e7ea15e6f6eef1fe704e523544d60f7ea4bc6e6d7" },
                { "ka", "e6a7795130bccac8bc8bbc14f4e622d8402d7dcd42adb8371d2684fc3d0e6eb4f890f55c2a1923f2ddf8edfd7538ef95633652db306f7b8f20d578c79431977c" },
                { "kab", "406e7dd3bf4613533b214a894c9fca2d08d1c6892a505f8c6b1fc21bc4a22b1d168ae6cfc9a0fe1bbae178ab3e69780819e8d5cd5a4a0db09a067cb81d01cb8b" },
                { "kk", "3f6d798830cd1b9ccd8190c74b669c561475e6239281e82b3603603e840a8bbfc79703735794f8c0c374368b32d08873ca65b1aaf0e13f20dd5fb45445658e5f" },
                { "km", "90d1cb3b2da5d38783207c27884549a7ffbd3b62785b60d99c5de1c022878cc33de03474467e18dc11230b0dedcae4bb1da5507995770b94eb44464571e301ad" },
                { "kn", "765124d6494abf814c791c98f9a63429bff32fcbee81b207a81fcf4fb4c4547966a746cc4121f37bbc87cf979d159d66a5b62cb3f32d8fcd0e7d0bef95c1ead1" },
                { "ko", "9e97de2de3a284f232ad05b5ef5fc4f33b9e2b04141f0160a06c502e0bee7af47c856fe37457e3159e496c187250392ab662233a96026a66607e81277632bbf5" },
                { "lij", "c4c0fd9bfdce62d8a890641bf4f1fd439830fcf97a1b8f98f9625ac53faffe1c34d40a5ace860343d86d715a45fd2570d29f98acebfaf97a86e4689c0a09002e" },
                { "lt", "a96d2d39fe761d4eed14d6abe7ad21be8a2548170ea5694aca3af91edf516d10b9393e1648ac6e06896b948a0c395a59b20a5bd7adc146d103a1be51ac05639e" },
                { "lv", "41f84703e437dd11af1655f5ee728dc1fac0e78be25f474f8de38b4a6f3b6c6ac3e5e9b4a858f6932881ff60c40b39e32f2b282d2cf6c208480f1c03c403d8ff" },
                { "mk", "08852130e1d483bef735d66c274be8f1036ef6f3367de37ff90923f59f6383c647e3e193d338f6ada85a8b8461658b3ee647fbccc123c02bd1d39f4105c59446" },
                { "mr", "39ebf817b5e917252f745fa5426db49ba0acbba87ed56a71e0a94af34cc55354782b5b4ed7bbde9df4d1a404c84294ecac02d58d49061b96a9e835c267f77884" },
                { "ms", "b8c6ba2ac29f259b35e116de62e28c48777ba490093e22aa6757c5dc7c949420713d66c0f27afd3b457327ee5c63dffa3d957c83633ceebfeccded8dd25b66fc" },
                { "my", "fd1297814cfec849d7115e7861c831e891e71374ee50fcd23a897e51b393b9bdb098c98507f4acfaded617e344a5687227340edba516bfeb29535be06297e253" },
                { "nb-NO", "940877156c52071d8b5b6b207ac1e958495460949c765a0db2667c46f05296d7c01f7ad6b11983d4c4f7bbedd13a6ed2dc3828499daf2a9b48f54aeb30e7f1b3" },
                { "ne-NP", "91c3138a7d7afdbb8f6b125390e247e32169f69793bfa2679120bdbd6a684b1ca6fb457c4761c16cb8d74a4d6a83f408ad75dee0541a78bca59a8a37270a79e9" },
                { "nl", "cee9620d277d041432540c99de2076454316b3f39adca66fa9b9e835ede09d3210a2331769634058481fd48d8374ed5059afddc4e516d336e2bf35ed6e31b7ba" },
                { "nn-NO", "e23bda8847f5920ceaee3f51264160a49d9a7ef7c0f9f784ec44289e77b93ad086d77c988d1f2cece183c3fb642c463125f282b3f49f02a2d7ecae16a88c6545" },
                { "oc", "465c5bb70dae9c3d9bcc01d685bab044b4dfa76d2e92571d1a452a0bf4aaaccc553f76d339b7b2256258babc9fc991b779ce56a7856daa6f389b288b46f0fdc8" },
                { "pa-IN", "8f9a02524b2e544a9fe5d13980ea8b56cf466bdfb90084f89d23477afb8556720589c4fac5afde86e95ba46434f0a92f0f5f4efdbced42f8f4511e458b5288d8" },
                { "pl", "3421c03bce1777d26bfd4a4a67ccb79430039ca01930393b3feeb81fad85b6a35f4775996a8cd4434f43ed1599dbd828e5c7833f506ebff07e8546105c88876b" },
                { "pt-BR", "c24e9032a3825d6c13088a12df59bd26b46a47f4d89fefb04557c036f124fdddc980e0e588b1481893e57497798cb30ceabf9505f94f57fe6fc32d804420039c" },
                { "pt-PT", "7e4770b1f0375620bd7f5ac1048a214e8343c64de6834334792d005b4c97bfd53e9e8919b43902fe22b99354b9af1bf6b3f5b93ac95a6b4015935b2d0f6833da" },
                { "rm", "51cd123be3f9835057fd4c11f88a2d732641be2c14a87fd02a1ee2b2bd6e2d513370ce6f9e770d4bc1817c9ff35e5a0ab5c595e6cb4b6846088ec500e6cedcd7" },
                { "ro", "4662c8f5605d69a5cbd2f0d843d519ef6797430c3fad0805472793f979b4b2c8a633101b36833977dcce83ce99ea6e27ba15ec1a614e261feaecc0e34b3da4f4" },
                { "ru", "1ed8f9c249a16581262e8c33c5aac088a2d82e1ab6c15baffb54ef5ab40e9039b3a5c687226d5da91d2fb29b87c73686893bfb4bf9f67b1c214c6b5d622d12b0" },
                { "sat", "621f16c6e2041d99caf792c7fd15e1d86b5a91e558c158dbe656197147008e6c8795e91795ea9372cbffa2a6b783cec96aceb1522ae0772215a7d03904a247d9" },
                { "sc", "7ff608bc75238938d6b441c5deedd363d9ae249b6a6783f5a4a4908d7c1db61b74942432574521f933f17c8b9e19b4547b9f729d0cf6e5e4cc02cee84506f4d9" },
                { "sco", "378a789e213da216de53601a834b3cbec7ec9b4444e3bc431417fd6150ab7fb1971208435d9a881de9a8dbfaa9991d0afd96116bcc94371158d6dea6f7fd302e" },
                { "si", "ca13337c7bf19d9bbf3bf3c19a933b0c8af7ad92bf7cf7d9aa126526f478d28f25bef42834a7624552f2cfde55b3dee99f0f90e0f3172d897eeec128ec48e78e" },
                { "sk", "a494beca9a63ebf17e9a85b57a8f484c1e9c020f000fb29f784a0f576f29e38d57523e6714179b30327e1ead3c934dd59d6bfcadff84fc1afbc3f2a62f578813" },
                { "skr", "5d4b4e9d80f4f0073101f266eca305a37c7fe23781ec56777c4d4845c26b967171b19e103bc1e86e3b124254d996926f1a8f07f69fee991412601efedd5f3af3" },
                { "sl", "4d5c4d13fb05d513f3dd44b219f32663996508c866a1ef60d5fad6625a1962a168f86dd60b536ea6e8b0ba0ef0b5162b773d9cbc6a50d72ac21858089d49ab46" },
                { "son", "cb980c123458148e2867ae0c369c791fa466fd7135641f9a1df7ab8ee0d678c74a4007f7f7c8169053c6ca2dcde7cfd86217e6aed1c651692b1ddc8e8f5f8603" },
                { "sq", "7502cac8a29d65048d28e8ba31e19ad241b09082061c485f3359f05c1497015ca1fecd060009fff55279486a7b58d7572ac3d63b6b2b917d3aaf228c6cbc87af" },
                { "sr", "9f26dfed9968b6e2186aa5ed2e6d43d7ef643f6e483c24a5e1425983c4ef1581e96116e32e64881f07183d3baf3a3545e8477ab970eaa808d99d6d52096f6578" },
                { "sv-SE", "9395ed624ee96d5091f228192b4ce0c3670ea72068fa125386bea0b7128f91721337e7f7f76d3e3b61810462dc8f55aa41588f4a02c3952b0eb1fc500a3354bf" },
                { "szl", "f83d555b7624fcf9d9037d91eb8d9af9bed08ee30f9a42a52ce47946fc652b88237dbf79e034c2de82a2b3639001b24cf90369b1c52c0640aac711254beb59d2" },
                { "ta", "c0947b5388e62d83762295a0220affaf781f7d25477b72d6516944ed9f8b79beb63bd7fd8eb3332beaacd7e07eee316d5b8eddd48e231cff4fb5d66f08f64ef7" },
                { "te", "f70e3f83a826c0aba4f24993fb4156a2c65b7d6543adccbcd05fbd9283923b199e3812c1b6a6747d1b557be3fe0312005abef9ec99240e84dd1a332520ef997e" },
                { "tg", "80f565b5111e56c0f0f9233c1eaa607066777057aa5f6aa48f2e8ac4eccfa4b57a80c9ea01addede6f3fa71fd8c9934c0363801ece8cbdee55bb6056cc3baf51" },
                { "th", "f65b0de42aef3451288b8c148ab39f75bc465cde379c84debeb522ca5983e9f56077f37e1b4ab29b46babb0dc336d1bb543c948d02cff51af8fc775e3ae0d934" },
                { "tl", "8cccf4b6e38e54806920fffaa4f14c7d7b32b25a33a42e6ec2e526278a6471eb74e796b29a260f1570c515463941fcbf033831f5617b3dbda69cf2289d20fa63" },
                { "tr", "c923d97cc6e9f2e43d3ba8f2358de79307a4b883591236a1c8e4c09538de71d7e16faa5a288554db0dc57d5ec9dd75d542d66cc042a65af6a7cddd7f476d3af6" },
                { "trs", "21c6b4a607e6f802b96f61d046edf08cb1b3d2406cc49b54749ead98f9310898bce7c41d4ba75964dbab02c3fa9c54f6e392227decae0ad72b921b5e3219ac2d" },
                { "uk", "0989805834142a2b1663a12884e60d293ec2e248e585580505df1b4e00633aacc3ce2077edc0e13bd3dfba05955001426c2482d0cb4e27891e24ae17fe2b37c2" },
                { "ur", "84e9c09f619d0a11a3f9576e6022123fdceb314f3cb8630f0a27e96eb2d1b4dd06bdf585eb1e1fc5802e982717d22d285fad1e7b83482a1e893fa98666c632f1" },
                { "uz", "ab7e42e85673cd729be6772b3a426af13f4f4541894a3ca515c43bb778bc2bc5da481f48249b14136dabccbc0c6ec1773abf36e71d48e5b863089ce2da971bc6" },
                { "vi", "54e8275d4c72f7976c580d8499416d4123934be83318f65afe62dd5e09697267223942b7b627a21863113cfa7b7cc8eaf44a510180e38cdde6d81eb24d1b5df2" },
                { "xh", "b30de6930b2d566e98d06e4a63a0b6257c464a65ef1bf7fce9f9a88c958e8627de6ededb47396e33b1537c478e62d6265d862c4ce1b5de5804c7b564c7cbeb56" },
                { "zh-CN", "ca204760d4c4c1bcbc2ef6c782c0a919e6aa7f92577848963bb1e40992d0ad4518bb53d92dedd7eca7843cd70afe1c696bb0377ab3388f6a31d6f618e324ee01" },
                { "zh-TW", "63b69930ee3bd60eb40ac0c36f658831fc1acc239855fdd41eee6f2ab80e6ea330827e5b9ce97264dfaac5356eca89fe45cee05bdbd30af495623e959f62beac" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/153.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5b1a9be75fe553e25d89bbf9f9b990e61215a19d6b0693f3706d61b312feda6e4cbc7caa44fe68575c6c3462231fb11fbe79bb51cdda0cde35a242cc3449e6dd" },
                { "af", "ce4d4a6f9aa4c68517e73c2e5e9795d5fa2575fb4159a7f07a83c0369276431cf482bb8db9bc770bc4c4e8d24d0fb4ae44cbc55c3349269bbfd77fdb69455798" },
                { "an", "289097b167f09a041879a7df9a1d5e4e7249ac594463e2f964a1b65a080d0a3b608ccd84a2dc7cb6d8508dfa81bdec56bd277fd7fda76e6a0ac4a59151d536a7" },
                { "ar", "c5b4715f8568c6e6642f7626b483623c35ecebe4525a2b7ac9f2638f64787618129554af6afecd5d0afb2ec0cdd3a70b2ef8dca858a88ceaf1855afa806057c3" },
                { "ast", "36fcc76fb16c273f48dacad62e93c07a3094d72b6917ed3664bbb1a92fc1b744cdb2d769d7c65c77ab4322933bafd43cc63c6b94e99893504acb1e2482be38d6" },
                { "az", "84352946a547b32ed50e83538b79ba5e200f39b87b6f9c41a6f709d00e617a40d28a82545c31a6c23d9ea321e7616177aaccf7e30b0ebe56a6534b397b800d69" },
                { "be", "c8bca9c46eae733351d50b4665b6ad646e96d79b6229912ea34d41cf359080b12647dfa592d4cefcc26afa421dd998eeeba4e961df22be94e88dfb5a013c86c9" },
                { "bg", "a002a8696491a16d9cf4038cdfdb0956b5a41230d1bedbf1512521f268a6b2858af96011dd3cd7085facbb9c37b6e6d553402d02862ab82c424970c2dc9d6be5" },
                { "bn", "0596eec17725c7778a64ea57385ffadeeac72ce2401a9b6881233521729db7a0e4ae0a09d43c9ab4ff8af87f8cfca8833dbf692ee952d8dc58a1bcb181c1a183" },
                { "br", "54b0b70684f2d02c099b3751be930c883af2d12aa0e753dd60cd3c45576556ef0454d06daa5a14b11c00f69fc346480d1e11604e49255db164255524ab8d480d" },
                { "bs", "975ef39464c1e7d95a7bafb5bcd0240cc7d9ab95eef4903d14a36aad9bbc404a6eae1fc324699bd5903539b56c4fbcbf80304c1f7ba02323e864befae65b06f8" },
                { "ca", "b31df866b96e3f5eee8daba2e98b4aae0d0656d598ba91ffdbab8306f9edccd89be05896fd80b328019a617aa9b6407646be77565280a8f24d7300bc5bffb33d" },
                { "cak", "b17b4ee5b8089b9bc5a139cab656b76fb486d42130d5f2d408c11fb2f72ac28b20f2d3d74f92c3f14ea575c35eaf3126dae2cf710390d0ba092462e9b879d5a0" },
                { "cs", "74a4acc08d30a97fe7c06ef4d5b2369c8e07788fe200c8a8277c3140f96b730e155487f34b4d27a9cdaf7c645de2482093f42dd8348b59f67dc5ddf2251c14b3" },
                { "cy", "6b8cf67a361a47bd353deffc5322481d223c310517b7c0e4aec9d7785bd292a6a3bb8a7030c1110784af64efd7d6c98018c6018751b186e96f3e63eb15e99608" },
                { "da", "6fc9f6bfb60e8509d9f8e79dd67816e73896fd37278c42fba3c97365adc48fd00c0da3e751b3e2e17f4c8bc0576322cb92a23fc7266340a2ba65394ca4cc7f43" },
                { "de", "0c0931fd1ee878ce74bdac888d9af67987cc776f2ebe7a1f16896d7281445c04da021a4dd89d800b55b1008a533906d443399de97b4aff767c4f83fd77132856" },
                { "dsb", "239c65bb5e113a19c840c95ffa36d08f206004f64eca64caa11bd1db1515cb735197846045ea5e9baba837c1ad689551acc9d0e1fe961eefee9b139678a063a4" },
                { "el", "2cb45af175be7deab254a3ad2d7776b79291e8657baed00d5c84e07fa164b5a63155b780ab87604b5e634e643449604e80128f7ea20fde7410597454ac4e2a94" },
                { "en-CA", "a0dd9fa60dea61a18e375ab56ce4e752976846bab794b265b38777a1810180b7901919b6fed564c8721caedf4acc69cd8cffef48bb8a3d7ca1e6e1d482178441" },
                { "en-GB", "237a1bd86db42fc414dedc5774d0bb0fee470d51598a72b12c289a5d566f33cf1251f9bfbaef543466b7fda45758b0aac7a1e91b1ead8172e1e281aa2dff6fb4" },
                { "en-US", "9698b1a4dd42ed5d7bb84bd55091a5ff82bf32f1a3bd1fd2c3e40f09db14554882f4409ebc713deb85162a459686d40731c96d8993e5bcd68cf8815809cdf485" },
                { "eo", "ca00b0e55fec5cafe8dbd13c22ffe606f63003e671a4a8bd69df7a54f9fd8718356704dcc5298f8acfaa8bbccb7e9e29241460cb5f1f7da5e0fbd9de3e4d849f" },
                { "es-AR", "bb90a2c0dd9b2c91081b8e235e0150e560be3b5745385ca3040d5597ac8b53392f9b8468c501618c38542bcfb027ac14ee63a070900f1034edacdff7851d7cfd" },
                { "es-CL", "e9134faa01606fa2c81be372f7604fb1cd2f01cbf5dba658f13fb56c03a859e3c262c10482a7543c6ed40be8f0362fcda45c3f09459807181f326d826f1b8435" },
                { "es-ES", "9bbbd152a5e487dec19de65027526001f4bb6beb7959207c8b092755b40bdcde39102a84ad9bf24fb7cea7e134f5531aa7380576e309b8edff367280e67fd99d" },
                { "es-MX", "4ac7b8181dad11148a6950a40946329774ce5ecac903dac163e3061da3c83c03714c1cda797aab3db691cec13ed2390e2a18769f29a1c4c49d3024a3e486a278" },
                { "et", "1db48e1ae2bff1ec17ce904c8df76eceeb5d9258a751f9d9b0b3c60e71d4677ece6cf0e58e4970f5e7ae868f001ff539c6c2a3ecb503f33d34656e08e4ef3ca4" },
                { "eu", "d0e481079b965c1246f556842b2615f570a8b4481cd27efa0fe32961fc8512e48b097540ceffe1a97b80c13c722e2ddba860ae4054f2faa5cf4b14ca7d1394c1" },
                { "fa", "6d944ed8d6e61cd61efcf071b9cf327ec77bc1803508d4f93880b3acf4ec1f871de218160aac8cbc01f7a1d11c8fa5b443a26719dd97438d08179f21a86cca18" },
                { "ff", "fd1174b7ff1d267728eaa85a8023370fc2e65cebc53471472769eddad7b4304cba961aab78024ced9a3720d3aed72972f304bd19771d69f651324a1b3bb1463b" },
                { "fi", "b368ff82e7c0c1d28a02838ccc1cadeb49b0c23e5bc437626d7f76900efd0edf965e9e70b9aa370a319b5e18fb7fdc05bf062bf360a7a5ca40eaf2b608267a05" },
                { "fr", "b14c8711452dc601ae23695d072d7462e4e49f8f7c1ab2bad997177f6213380abbdf968c38eeb366c566150168ec7a0e17f9f75be52c5e8cf8605d9162e5db0f" },
                { "fur", "b516b4a30e32d4c390f349b9c1d4b82e44fd24d2c6bc00be61ba6a88252ac9344d2d871f637b4dc72ab68bb193460f543e4d6d9369176f2eda4a6978a580b2c5" },
                { "fy-NL", "d9a095e3289b962dfdf02473881bddb18fa9833ea3985f36661996b5cd380c5ec1054ce2f5cfe5d33e26e509f5b1421e4885e99e874aef75a8e6cf74bb69e22e" },
                { "ga-IE", "2c1512a7797569eb979eef935f0b2433df718ac854902c4c7887357e835010053ab48e920510b19d542d2346d168404cc0f35a46c94aa0162db906cf0fba66fe" },
                { "gd", "aa422ce41780a42bd04d63e44c0d4ca24df23eeec419532fd400a8f115bdd73165fff8650c34dd5ba2256661756fe93272b6dd93810235bd3150edf8e37ff111" },
                { "gl", "e8999728aefdd81368bcbaa8a1d622a5bcd48f53a3a64909112c5d201f385bc2ba443ee4e9e6668180a5120000b0e781d4396e5e993c410fb091de8880d6e13e" },
                { "gn", "be21c076085686da4d6714700bbac85a6051391ec7ab0b6c32ea6e7de956bd209befd788ed068dc9f8a36a3ce65c105dfb74c82e33791a14201cc7cc7062c74a" },
                { "gu-IN", "610f2f19bb92fb3071b4198b648eaf5c8f062da0e3734ca9d687519a28e9e9f6c4bda97c80d19458bdec3a468e3248ab932483dd8c53f3626addbeb2b2b54c2b" },
                { "he", "1de807ff6852c644acdfc44c92c83f70d189a0f8cb6ed4f0897b9977c0f1a05f8bed40be7c362ea4bf8ab1d5851714b67d161c94833673b70fcaefbc8b427dc5" },
                { "hi-IN", "07021efaec579dc3b885a23414811f26a1ae6cccc8b73e6f50c58f32d0c136327d512d6048d9f1e984dce6cd03488ddf409ff5141e97f7b6005b7ea5e2f292d4" },
                { "hr", "e463aa221d42c424a85ce721148a7e0edc65c4b051e8bd9d589faf37bd59ab8066c2038d19413272cf5ec21ee62006a101fff09d001ba15410e1ea048d00de68" },
                { "hsb", "8e358416ca5e25401185ffe2e81ec68dc5b5c68d0752bae492ba2d88cd191a48eedfe4af90ac7c0b285d10382f4363065c06bdc5808398da2f61ddfbdac44d24" },
                { "hu", "d59a265f48a338fe3d6f595255d73b16c180306f24469dfbe930b49ee549f637854ec88aa6fd9f14b182eb10f0bbe8282ef8fca6a6ba65ca2928d184caf0bde1" },
                { "hy-AM", "686220ec05924b9efe509cb24fe1cb735b1e40504336cc70e5f237e1a9c963624e79c7cbb9965e5b0ca0ce8cf9e75059ab6cf0d4b557f66ba6912bc930aa34da" },
                { "ia", "8a450d0bb010d717539a2e64b7c58532c261c62ad0d49c794013c6f314bc3a3aa19b32f57ba85dd5de49e3989728e86bbd7559cbe6f9fd0a9b771d91f2115b9b" },
                { "id", "547f9d152e6d5d87eb7a71ddbfee6ec726416328edfc31898a27276f7c4c7bae15900a06916dabbba0dc8202fd6a027da0d011c3f350a9fee6b5d0a14c53f450" },
                { "is", "632436a3273377e7cc745f7acdbccf2ea5b4dff16c256913cbd926c86ec22da49f24552e8c757f57a418843362de4eece425f4fba5eac52a1b480afdcb6269fe" },
                { "it", "fbb0a96d69c8444d550b98fdafe3b3d6c30acb36d76d73054a28d90f7d3cb497e891c45b33e6193060833420ea20be300a54739a5ab06f3a1226aa4b4aad9a22" },
                { "ja", "737c85746ddd46c303595946a75511a41ca8aac6b6b5a39749ac2325b3da28d4d745cf9ce02b1bc92bb7b2284584b98637b819e8db6b5fd45989399692509e42" },
                { "ka", "aa12e497394e2fedaa7ac57a5c2b1e12a5a0a209d5deb7a0b430c195aa0268bd3a5b67ae128e4610d50b4ae3a6eff0925246155a56d78a171e405c3ce3731c89" },
                { "kab", "d12240d8369a460017a8af09b7d4b90fd89bd9648ee62021004b09d4e4a8a3fe53362f36af7a0808c53c5f0aff0936079b4a6441af2a12b6c501f359f17b1e4c" },
                { "kk", "d5acd961a422d661afaa82efbc023fd3dcc6e6b8df09a041cec8939253fcab630f6f1dddc79a0b83cca86ffda5e10b8ab4e3fad833e523bfa0c53017ee5c15bf" },
                { "km", "bced97fe633f7a7e163baeb1168f90bd9a2d297d631b06e6f36fdae81a58fdb35f29bd3150bb13c48c305b2856080db1d6eb4ddd5934718c3ecf80dd443422d8" },
                { "kn", "bde3eecb2a27c2fa1551347172f93974e093c22357333239cb8941b9d19cb53c3e3b61b0d8f2ef748a571af01ad41e952ec9a3104be116eae30084de3ea44e97" },
                { "ko", "246b6fbf46d787e69ae6e4400431d069afe475f9ca6b55cf45ac9722fe3a7268625158d300c20a49051021f2bcddb7114360a116cbfdb6b1407c4bd66b3e2175" },
                { "lij", "a3eafd62c8d1603adef30074190078056363f3b81dc8d2a4bb48d726423b738c0619d9524dbe8a7a287de3172a1d6320229e2b8d246f5475d748892fe50d0934" },
                { "lt", "81e205e13bef9dc83e36551feb7b3b3834d47a50c39a674b92ea1ba0c05483bcb85c4a30baf70c245215ae34bfcd6263f67c8c4d77667d1f2eb48efff98537c5" },
                { "lv", "31b88a47ae8ffedb1ab76bbaf7902fba61ae72fa632ae2fdf3c62966a599ba954af407b8b3358e829ea9a3df52676e08ddf65032cade6d6250aca98d81c65970" },
                { "mk", "99ba9cfd85a649b3b918e07accc024ef4b3502cf77ab23e66c849c06ec4bccd74e7a577613cc17911cdeccd83b2e0d32056696d6563aeea2f20fba385f7ea0c4" },
                { "mr", "c3c25e19a87d6dab4237f1bd667244de3b5eaaeb640f032ae7e5d8e44775ab34f0a4708c10dd6a50f1bf23547eeac94b5dddec5c409749fc0e66474aa1ecd64c" },
                { "ms", "a413e88f1eab2ce8e86e2767c5ea9571032ed500849a41470e0d1cc0061400f8357289fb91029a644def7aeae1011564134cb9c8a69695d5635355b32da0e67d" },
                { "my", "ba83cea3dae61cd9a071e03fa18f0607487c9cee5874c9c2fa3f4ba2960fc43bf24c6101689a76f741b554e71b9ad0f836a933415d38dd5e3eef3b8e38dde954" },
                { "nb-NO", "24b819c8d5d033dcacfc7743875977f34320128401d2088361e991f0db4cdd5217dd00738f7e933e6325131046905aeaaabb43c8d1011d9901b33fa2965e3634" },
                { "ne-NP", "1eb1f61b04cd516bdec174a06a215ad0bd08e6a34642f9ae6cf8e3dfd8dcdf61c884c4be781e2d589d9f423f3665431d7751b8206a6f7926d6ab51c2a3afefb3" },
                { "nl", "59d6da348ae41a57902d5057722b8cce096daa22d5cfc2064d61ac7853c330dbb9ff512730e7c7bfd4eb3a1a71d6bced7c36e41deaca60fe7f3e82f11560870a" },
                { "nn-NO", "0d097e3c5d4b0f534cd20cc37e1bc038025e29c5c3a282c4d2e1a9385150dccb6652e41df7c9dea277792ed93f7fbefa301d26da38e10277d8b7c82fb2f70dba" },
                { "oc", "75eb6011670eb40edeedb3cf32fa600ffadb4f991eb75f6614feb5411b541b655daedeae03bb59e1d2de756ca63f3c1c5940688e724a864de1ac496fd54dcfc4" },
                { "pa-IN", "f48c9fdcd6efcce3be49a646c356dd8efa31b84fc80b664c78ce581e2ed937eea0b02a360146fc4e1ca0933a31cb8e960a5af99a71af9322d4e88f7cc629fb17" },
                { "pl", "4689290c8ff40e12bb105961726368252e4f95a2ef52d62f5433d72634a0a596b276b57273a65c663461b46f18b3d5ffb0aa2965877dacea66f9fa7b5a76677b" },
                { "pt-BR", "43b3b44a851d6e565ca305daaac8d53e0cf0701057f830300b58fe344a40f290d83b7149dab3421065fe1b185bc2eff1afb0147ee51e72a5fea7c2ff2b08b48b" },
                { "pt-PT", "274c87c56ab781c7ec10b00f8bdab7953c712bedb689d2e191e0f54aa2385af0ce654e5213433d0d6032c0ee649408ac39ba1964af094177060b195a37dae2cc" },
                { "rm", "bca3f3b74d4bc2574266c4ed397205da8e1f97cdb2d681e6bbabd40c669fed746a0ceafb6273b69302f15ed142c01bcd8c06edc428dbb300a02e67d6347c973d" },
                { "ro", "30e62949af5004600fcf7feafaa9e3c23e59011add900e72222ce3c4724743de6810405a42ddffedfa750087bebcab2ad997e3f46b368d55e6ddbc02b3ab5173" },
                { "ru", "6f2db13b0f82a6105422dc58366c5d3717292cffc3d3a5949157b769dcdd58d494d545aee29c07588820aa6ef8e210e15584e30a6aaac04313aec199e0a3e7a8" },
                { "sat", "465426aaf0ea11e1970bd91b89b8df6c81900633bdcc91c53dc949a59d9d9eb8193780b0b8e755f8a47d636af02d3556d8640504b25f4662823050024fbd1657" },
                { "sc", "b59cfe2846fbabff4b06e48e41909b70a1ee3e38892e8206dc4fe15aebe86e89eea249ecf9c6a1b9ed1e374e6fb887a66103f5c1a0a38bfe57e81e8176029861" },
                { "sco", "76a2763ed564b8bcfc1ac38d0c502d8cc27a6c99b4974b7c8db1335ed68a1109077eca2bf26398fe17ecc4d069accd16bf657eaff267648683f5639ed8113890" },
                { "si", "3d5fb479bc0a4d0f97f1c3696d85683facee3c5bb43618d0e6ecfb6239dd6aa9952feec03c5ff2eae31e336300add8aa5caf8fbdab7cabd0f7b1d6aacc7d096c" },
                { "sk", "43f6c35e40c269d14c0c57e8079c12034f48a60cdf61cbd8a9acaa26016d9f3f094290055d7a7b2db44694ab4194add53c66b0407913ca4bf438220933fbc566" },
                { "skr", "f03a5893741e9285120b51adc2f4b2d7d14865333eef412c8d4658f4874bd033df03d5582d533498f16f8ebaa9a690bd57d35e0604937edcdb5f6a221e536bfd" },
                { "sl", "c0193d307d25817a714f2d08cf0eb7e8569e694b4fd2e56defe268f03ccd7f3c4be3968af0c1312c81d08d88e98cdf3c28c3c2ea9bba84fa554f65dfd34b4c87" },
                { "son", "a196f028840d09427784c33389fa62d2e9ade2fca0d6484be44a4dc906511c792664bdfff82886da720c0d23717b7a3c328619c31729163b645cfcb0fc4f917b" },
                { "sq", "fe3733a5275b8e3c6e2289397fcc170de976d1358f04aad128cd1b91ee9911bd39399730926e1f755261288df9655f23d5e52836b930a38ccceff29b89948875" },
                { "sr", "ac7acc1d0c655495ee6152d693b6301bfd0568ad588fab4d3c9df5c67642b342f188570f6e5d6352fed2af7d1f498c0b6db05ed83fc1b5e73a3a7add3fec2b23" },
                { "sv-SE", "2f201c510dd6a25e50fc7274b7d2617ae9ad609b428d44c8e6ac97b929db78c892ec7ea937c278a46ad2d2a6dffe665061f31b9d6f5f2915098a32088e850a54" },
                { "szl", "b1ffec06cf9766e57b4ce5fa572705ec335a8236c2e3f008ba5626443e4208c5634c72412d2b81546f7ec0ccace8a3b38bb677d91a60ad793d926f88f20e63f3" },
                { "ta", "9029993acd62af9d866aefa1708885b08aa3cd7cfa1da64247cd283f07200d11d052371cc5e8de4c7bd4f17709d8756acf61020e8fb22f5ba3fdf2456b6648e5" },
                { "te", "8f6f4956d010e8989d2909c2b64d5a2c38d7a304471c942a48dbccde96f5b3506fe8d29a2d69bf78470aa984126c0a2b35207790d145a54d5dc880273523e443" },
                { "tg", "70812b19b31bbd7605d995f456286a67afe789365a11090f0d1f99afdfd5ee30e0be5bfed9f3efb0283eb2331a992be4ea6c1cc25456d19044742d19c5317f64" },
                { "th", "df12d24687c5db71f84c7047e477c13a845d4553f1992567a6fbbfc165f8597e78a6f5e8ec40b3db6a9c54d5748af59a1592493ca1eb1a87e7a4dae1bba2dbd6" },
                { "tl", "b78b2b5c0f7fc4b13b129fea3d65bbeb1d31769b011e81cfee2b6f9b2d4d1d9e3ac3ac0c498e211d1413cac0ba6d0faea1b63c094ccc618fecc09edfb0f98f74" },
                { "tr", "c8ce0f918be3c887644e35d077662524439a12c099479626a9d75ae65ec8e7c06ff42e59f3a5b8d9bfd2c66f04b9e0271538b073b33b11a54e62edc66e4b1de4" },
                { "trs", "00183dba31ca7de5bfd0c68c45fe5927fc1caedf5ec0f84e210592fd6d9f5c63da6db5ef2ceada87bdf93770a1540fd041d779263316409db61fd8feb95b2a7e" },
                { "uk", "a08ccc4fde574c5252e51b5ad43a601c34f42b81d82ec876a2c54bc175e3a547c7817ce4c867a3c28b6f21ad1fa1b2133b5b9bd6a4acdd113fc2c8be38a19e07" },
                { "ur", "9af7086d25d4e051fdd2859759df04499afd1eb9509bb4be333d5d2506fa3d988f84a20693ce26f1c7d3075520f5631aa1700f910541a3d7f80d9e901ff954ef" },
                { "uz", "ba3f61af37b0cb39a09bc6cd96807abe1bfe7aca8550a451359e91c65d855568f32e932d7d1a46128f4d2180e95e14c23378cd29b268dafc11ceb85a1975006b" },
                { "vi", "e2f78e9d374e439a4683bbd8f34e1a94e0e2e0fe2a0eec5a0bc458f95757cb6bf2041c1bf11eb90e7ff21dffebbffa2c424b39511a0e163c75c93bd0eee9df9f" },
                { "xh", "13dd8701e13baae1ee505c7b2c230adff339f78f8ac2ba51bdf9ae9753ce6d547e1a5de2d9d68a376493ead321d57b68a1bdd47947850ac73e1610a265dd1b18" },
                { "zh-CN", "3e393e1be1d3f5d06140b70ddb2214c075422a6eeaab06534e490c42544167fb38c5d0430711d4fd7117a8f50867035fc9ab545a5ab5c3a18fdfd59b1fcd61d0" },
                { "zh-TW", "dfee58a8e5ccd6e985aa82617d818e9f091a6864b22ce2e21d3832dd9eee2b1f88f9ca3e4f44ac52c65df18e5ba00a3de354b81f9d045670c821b1a8dad53828" }
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
            const string knownVersion = "153.0.3";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return [];
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
