# Photos pack: sources

Accessed 2026-11-20. Round 1: 140 photos from Wikimedia Commons plus 10 generated screenshot-like images (150 entries). Round 2 below adds 154.

## How the photos were found

- Source: Wikimedia Commons API (`https://commons.wikimedia.org/w/api.php`), `generator=search` over the File namespace with queries like `pizza filetype:bitmap incategory:CC-zero -MET -museum -painting -drawing -illustration`, `prop=imageinfo&iiprop=url|size|sha1|mime|extmetadata`. 95 queries across the schema categories; 3,780 candidates.
- Kept only `image/jpeg`, long side >= 1600 px, and `extmetadata.License == cc0` (LicenseShortName `CC0`). Every selected file carries the `{{CC-zero}}` template (it is in Category:CC-zero). Licence in the manifest: `CC0-1.0`.
- One candidate tagged generic "Public domain" (`PD-ROC-exempt`, a Taiwanese official-notice exemption) was dropped because it is neither CC0 nor the Public Domain Mark. No PDM files ended up in the set.
- Title/description keyword filter (people, portraits, museum objects, logos, historic scans), then a manual visual review of contact sheets of all 220 shortlisted thumbnails. Dropped: identifiable people, artworks/sculptures as subject, brand logos or storefronts as main subject, a memorial wall (Stockholm 2017 attack), personal-name signs, museum interiors, near-duplicates.
- Client: User-Agent `SandroidResearchBot/0.1 (dataset research...)`, no personal data or contact address; API search calls about 1 every 3 s, thumbnails for review 1 per second, originals see Processing.
- Openverse was not needed: Commons CC0 alone gave enough phone-like photos.

## Processing

- Each original was checked against the Commons SHA-1, checked for the JPEG SOI marker, opened and `verify()`-ed with Pillow (JPEG or MPO). `original_had_exif` / `original_had_gps` come from the original file's EXIF (GPS IFD with latitude or longitude).
- Size budget 400 MB: the largest originals with long side > 3000 px were downscaled in a copy to 3000 px long side (Pillow LANCZOS, JPEG q90, original EXIF and ICC profile carried over unchanged). For those, `sha256`/`bytes`/`width`/`height` describe the stored file and `sha256_original`/`bytes_original`/`width_original`/`height_original` the Commons original. Originals are not kept in the pack.
- `width`/`height` are the stored (raw) pixel dimensions; EXIF Orientation is preserved, so some files display rotated, as on a phone.
- Some originals are MPO (a JPEG with an extra embedded image, typical for Samsung/Fujifilm phones). They are valid JPEG streams (start with FFD8FF, open as JPEG) and were kept byte-identical; downscaled copies are plain JPEG.
- Downloads were rate-limited by upload.wikimedia.org (HTTP 429, Retry-After 600 s for this generic User-Agent); the fetcher waited out every Retry-After and paced files 20 s apart.
- Privacy note: many originals carry the photographer's real GPS position and camera data in EXIF. Sandroid must rewrite or strip EXIF before seeding, as planned.
- `has_people: true` means a person or body part is visible (crowd from afar, backs, a hand or arm at the edge); no file has an identifiable face as a subject. `country_neutral: false` plus `country` where readable signage, script, plates or a recognisable landmark tie the photo to one country. Many neutral photos were taken abroad (file titles name the place), but nothing visible ties them to it.

## Keys added beyond PACK_SCHEMA.md (proposed for schema v2)

- `file`: path of the stored file relative to the pack folder.
- `original_had_exif`, `original_had_gps`: what the source file contained. The schema's `original_exif_stripped` is ambiguous; it is set to `false` everywhere because the stored files keep their original EXIF (Sandroid rewrites it at seeding time).
- `downscaled`, `sha256_original`, `bytes_original`, `width_original`, `height_original`: see Processing.
- `screenshot_like` entries use `licence: authored`, `url`/`page: null`, `indoor: null`.

## Generated screenshots (authored)

`ss-0001`..`ss-0010`: 1080x2400 PNG drawn with Pillow (a short generator script; not shipped in the pack) using Pillow's bundled Aileron font (CC0). Five chat UIs, three order/receipt UIs, two notes. All names, shops, amounts and messages are invented; no real brands or logos.

## Counts

| category | n |
|---|---|
| document_like | 11 |
| food | 18 |
| interior | 13 |
| landmark_generic | 9 |
| nature | 18 |
| pet | 13 |
| plant | 11 |
| screenshot_like | 10 |
| sky | 12 |
| sport | 8 |
| street | 15 |
| vehicle | 12 |

Country-neutral: 120/150. Originals with GPS EXIF: 64/140.

## Per-file attribution (CC0 needs none; recorded anyway)

| id | Commons file | author | licence |
|---|---|---|---|
| wm-0001 | [20190221 124822 Teremok Receipt Квитанция.jpg](https://commons.wikimedia.org/wiki/File:20190221_124822_Teremok_Receipt_%D0%9A%D0%B2%D0%B8%D1%82%D0%B0%D0%BD%D1%86%D0%B8%D1%8F.jpg) | Rakoon | CC0-1.0 |
| wm-0002 | [Menu du jour d'un restaurant asiatique lyonnais en 2017.jpg](https://commons.wikimedia.org/wiki/File:Menu_du_jour_d%27un_restaurant_asiatique_lyonnais_en_2017.jpg) | Benoît Prieur | CC0-1.0 |
| wm-0003 | [Wilhelma ticket Sep 2017.jpg](https://commons.wikimedia.org/wiki/File:Wilhelma_ticket_Sep_2017.jpg) | NotTheOnlyDreamer | CC0-1.0 |
| wm-0004 | [Invoice 04.jpg](https://commons.wikimedia.org/wiki/File:Invoice_04.jpg) | Shams948 | CC0-1.0 |
| wm-0005 | [L'Oro di Napoli - January 2025 - Sarah Stierch 22.jpg](https://commons.wikimedia.org/wiki/File:L%27Oro_di_Napoli_-_January_2025_-_Sarah_Stierch_22.jpg) | Missvain | CC0-1.0 |
| wm-0006 | [CA physique de février 2020 de l'association OpenStreetMap France en février 2020 - tableau.jpg](https://commons.wikimedia.org/wiki/File:CA_physique_de_f%C3%A9vrier_2020_de_l%27association_OpenStreetMap_France_en_f%C3%A9vrier_2020_-_tableau.jpg) | Benoît Prieur | CC0-1.0 |
| wm-0007 | [Littlewinds Favorites Indian fast food menu at Mahkato Wacipi 2023 cropped.jpg](https://commons.wikimedia.org/wiki/File:Littlewinds_Favorites_Indian_fast_food_menu_at_Mahkato_Wacipi_2023_cropped.jpg) | Pingnova | CC0-1.0 |
| wm-0008 | [Ticket 20220724 110102.jpg](https://commons.wikimedia.org/wiki/File:Ticket_20220724_110102.jpg) | 01x07x2022000 | CC0-1.0 |
| wm-0009 | [Shi Jie Soymilk King e-invoice FN16720614.jpg](https://commons.wikimedia.org/wiki/File:Shi_Jie_Soymilk_King_e-invoice_FN16720614.jpg) | TonnyTW 0907P | CC0-1.0 |
| wm-0010 | [Death Valley National Park - HCP - October 06, 2022 - 009 - Furnace Creek.jpg](https://commons.wikimedia.org/wiki/File:Death_Valley_National_Park_-_HCP_-_October_06,_2022_-_009_-_Furnace_Creek.jpg) | Vulturesong | CC0-1.0 |
| wm-0011 | [GZM bilet jednorazowy normalny 20 minut 2026 b.jpg](https://commons.wikimedia.org/wiki/File:GZM_bilet_jednorazowy_normalny_20_minut_2026_b.jpg) | Abraham | CC0-1.0 |
| wm-0012 | [Supreme Pizza 20250215-170829.jpg](https://commons.wikimedia.org/wiki/File:Supreme_Pizza_20250215-170829.jpg) | RegionVisitor90 | CC0-1.0 |
| wm-0013 | [Poke Bowl Kureci Maso Zlaty Klas 2025.jpg](https://commons.wikimedia.org/wiki/File:Poke_Bowl_Kureci_Maso_Zlaty_Klas_2025.jpg) | Mojmir Churavy | CC0-1.0 |
| wm-0014 | [Honest Burger with rosemary chips 2023-07-21.jpg](https://commons.wikimedia.org/wiki/File:Honest_Burger_with_rosemary_chips_2023-07-21.jpg) | Andy Li | CC0-1.0 |
| wm-0015 | [Latte - Oui Crêperie 2023-08-14.jpg](https://commons.wikimedia.org/wiki/File:Latte_-_Oui_Cr%C3%AAperie_2023-08-14.jpg) | Andy Li | CC0-1.0 |
| wm-0016 | [Ham cheese bread 2023-07-09.jpg](https://commons.wikimedia.org/wiki/File:Ham_cheese_bread_2023-07-09.jpg) | Andy Li | CC0-1.0 |
| wm-0017 | [HK SYP 西環 Sai Ying Pun 德輔道西 308 Des Voeux Road West 食神麗宮酒家 Chinese Banquet Seafood Restaurant food 紅豆糖水 Red bean dessert soup bowl n white spoon January 2026 N13P 03.jpg](https://commons.wikimedia.org/wiki/File:HK_SYP_%E8%A5%BF%E7%92%B0_Sai_Ying_Pun_%E5%BE%B7%E8%BC%94%E9%81%93%E8%A5%BF_308_Des_Voeux_Road_West_%E9%A3%9F%E7%A5%9E%E9%BA%97%E5%AE%AE%E9%85%92%E5%AE%B6_Chinese_Banquet_Seafood_Restaurant_food_%E7%B4%85%E8%B1%86%E7%B3%96%E6%B0%B4_Red_bean_dessert_soup_bowl_n_white_spoon_January_2026_N13P_03.jpg) | EVOW Sahgyune Paiem KAASEI 02238 | CC0-1.0 |
| wm-0018 | [SZ 深圳 Shenzhen 福田 Futian 七鮮 SevenFresh 超市 Supermarket 生果 fruit Blueberry May 2024 R12S 02.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E7%A6%8F%E7%94%B0_Futian_%E4%B8%83%E9%AE%AE_SevenFresh_%E8%B6%85%E5%B8%82_Supermarket_%E7%94%9F%E6%9E%9C_fruit_Blueberry_May_2024_R12S_02.jpg) | RagmmIO 6YAHAOI | CC0-1.0 |
| wm-0019 | [Salmon sushi (20250322).jpg](https://commons.wikimedia.org/wiki/File:Salmon_sushi_(20250322).jpg) | Fumikas Sagisavas | CC0-1.0 |
| wm-0020 | [Two bowls of noodles, a glass of wine, and a mug of beer at Kalandak Rooftop, Tibetan Colony, New Aruna Nagar, Delhi (2023).jpg](https://commons.wikimedia.org/wiki/File:Two_bowls_of_noodles,_a_glass_of_wine,_and_a_mug_of_beer_at_Kalandak_Rooftop,_Tibetan_Colony,_New_Aruna_Nagar,_Delhi_(2023).jpg) | Contrapunctus-1 | CC0-1.0 |
| wm-0021 | [Vegetarian creamy pasta - Jollof Café 2023-06-28.jpg](https://commons.wikimedia.org/wiki/File:Vegetarian_creamy_pasta_-_Jollof_Caf%C3%A9_2023-06-28.jpg) | Andy Li | CC0-1.0 |
| wm-0022 | [Coffee and white saucer.jpg](https://commons.wikimedia.org/wiki/File:Coffee_and_white_saucer.jpg) | Douglas Perkins | CC0-1.0 |
| wm-0023 | [Acre Pizza - October 2024 - Sarah Stierch.jpg](https://commons.wikimedia.org/wiki/File:Acre_Pizza_-_October_2024_-_Sarah_Stierch.jpg) | Missvain | CC0-1.0 |
| wm-0024 | [Acme Burger - February 2025 - Sarah Stierch 04.jpg](https://commons.wikimedia.org/wiki/File:Acme_Burger_-_February_2025_-_Sarah_Stierch_04.jpg) | Missvain | CC0-1.0 |
| wm-0025 | [Latte - MOGUMOGU 2024-04-29.jpg](https://commons.wikimedia.org/wiki/File:Latte_-_MOGUMOGU_2024-04-29.jpg) | Andy Li | CC0-1.0 |
| wm-0026 | [JP 沖繩 Okinawa 那霸市 Naha City 國際通 Kokusai-dori shop 沖繩自家製生麵 Yunami Sakashita-ten 板下店 Restaurant food 豬肉 Pork 排骨麵 rib noodle soup bowl February 2026 N13P 02.jpg](https://commons.wikimedia.org/wiki/File:JP_%E6%B2%96%E7%B9%A9_Okinawa_%E9%82%A3%E9%9C%B8%E5%B8%82_Naha_City_%E5%9C%8B%E9%9A%9B%E9%80%9A_Kokusai-dori_shop_%E6%B2%96%E7%B9%A9%E8%87%AA%E5%AE%B6%E8%A3%BD%E7%94%9F%E9%BA%B5_Yunami_Sakashita-ten_%E6%9D%BF%E4%B8%8B%E5%BA%97_Restaurant_food_%E8%B1%AC%E8%82%89_Pork_%E6%8E%92%E9%AA%A8%E9%BA%B5_rib_noodle_soup_bowl_February_2026_N13P_02.jpg) | NORTLAUKAU 26088 JP | CC0-1.0 |
| wm-0027 | [Stir-fried ice cream on Buford Highway, September 2016.jpg](https://commons.wikimedia.org/wiki/File:Stir-fried_ice_cream_on_Buford_Highway,_September_2016.jpg) | Thomson200 | CC0-1.0 |
| wm-0028 | [Smoked salmon pasta - Figaros, Brighton 2024-04-19.jpg](https://commons.wikimedia.org/wiki/File:Smoked_salmon_pasta_-_Figaros,_Brighton_2024-04-19.jpg) | Andy Li | CC0-1.0 |
| wm-0029 | [Rythu Vegetables market, Hyderabad 02.jpg](https://commons.wikimedia.org/wiki/File:Rythu_Vegetables_market,_Hyderabad_02.jpg) | Rajasekhar1961 | CC0-1.0 |
| wm-0030 | [HK SKD TKO 坑口 Hang Hau TKO Gateway mall shop breakfast restaurant furniture round table n chairs October 2026 N13P 06.jpg](https://commons.wikimedia.org/wiki/File:HK_SKD_TKO_%E5%9D%91%E5%8F%A3_Hang_Hau_TKO_Gateway_mall_shop_breakfast_restaurant_furniture_round_table_n_chairs_October_2026_N13P_06.jpg) | AGuo WecomU 2007 TAM | CC0-1.0 |
| wm-0031 | [Red Lion Pub Room Interior 2024.jpg](https://commons.wikimedia.org/wiki/File:Red_Lion_Pub_Room_Interior_2024.jpg) | BrooksyTPS | CC0-1.0 |
| wm-0032 | [MC 澳門 Macau Cotai 上蒲京 Grand Lisboa Palace 酒店 hotel room 衣櫃門 November 2024 R12S 02.jpg](https://commons.wikimedia.org/wiki/File:MC_%E6%BE%B3%E9%96%80_Macau_Cotai_%E4%B8%8A%E8%92%B2%E4%BA%AC_Grand_Lisboa_Palace_%E9%85%92%E5%BA%97_hotel_room_%E8%A1%A3%E6%AB%83%E9%96%80_November_2024_R12S_02.jpg) | JohnLEE Brothers | CC0-1.0 |
| wm-0033 | [Bare shelves at Sainsbury's in Woking, 16 March 2020 (4).jpg](https://commons.wikimedia.org/wiki/File:Bare_shelves_at_Sainsbury%27s_in_Woking,_16_March_2020_(4).jpg) | Owen Blacker | CC0-1.0 |
| wm-0034 | [Interior of Metro Espresso Pizza Cafe (Orlando) May 2023.jpg](https://commons.wikimedia.org/wiki/File:Interior_of_Metro_Espresso_Pizza_Cafe_(Orlando)_May_2023.jpg) | Benoît Prieur | CC0-1.0 |
| wm-0035 | [Product shelf in Taquitos Casazul 2023-05-30.jpg](https://commons.wikimedia.org/wiki/File:Product_shelf_in_Taquitos_Casazul_2023-05-30.jpg) | Andy Li | CC0-1.0 |
| wm-0036 | [Office interior 2022 queue.jpg](https://commons.wikimedia.org/wiki/File:Office_interior_2022_queue.jpg) | Rakoon | CC0-1.0 |
| wm-0037 | [MC 澳門 Macau Cotai 上蒲京 Grand Lisboa Palace 酒店 hotel living room November 2024 R12S 68.jpg](https://commons.wikimedia.org/wiki/File:MC_%E6%BE%B3%E9%96%80_Macau_Cotai_%E4%B8%8A%E8%92%B2%E4%BA%AC_Grand_Lisboa_Palace_%E9%85%92%E5%BA%97_hotel_living_room_November_2024_R12S_68.jpg) | JohnLEE Brothers | CC0-1.0 |
| wm-0038 | [BOOKCASE WITH SECRET DOOR, DAR KHALIFA, 2024.jpg](https://commons.wikimedia.org/wiki/File:BOOKCASE_WITH_SECRET_DOOR,_DAR_KHALIFA,_2024.jpg) | Secretum Mundi | CC0-1.0 |
| wm-0039 | [La Junta, Colorado post office interior 4.JPG](https://commons.wikimedia.org/wiki/File:La_Junta,_Colorado_post_office_interior_4.JPG) | Ammodramus | CC0-1.0 |
| wm-0040 | [Premium-Bereich DB Lounge München Hbf 2026-08.jpg](https://commons.wikimedia.org/wiki/File:Premium-Bereich_DB_Lounge_M%C3%BCnchen_Hbf_2026-08.jpg) | Ousw | CC0-1.0 |
| wm-0041 | [Bare shelves at Sainsbury's in Woking, 16 March 2020 (9).jpg](https://commons.wikimedia.org/wiki/File:Bare_shelves_at_Sainsbury%27s_in_Woking,_16_March_2020_(9).jpg) | Owen Blacker | CC0-1.0 |
| wm-0042 | [The Bystander cafe window view towards bus station 2023-08-07.jpg](https://commons.wikimedia.org/wiki/File:The_Bystander_cafe_window_view_towards_bus_station_2023-08-07.jpg) | Andy Li | CC0-1.0 |
| wm-0043 | [Berlin 20261015 Festival of Lights 02.jpg](https://commons.wikimedia.org/wiki/File:Berlin_20261015_Festival_of_Lights_02.jpg) | NutzerAusBerlin | CC0-1.0 |
| wm-0044 | [Tulips in front of the Cathedral of the Deposition of the Holy Robe.jpg](https://commons.wikimedia.org/wiki/File:Tulips_in_front_of_the_Cathedral_of_the_Deposition_of_the_Holy_Robe.jpg) | Vityavo | CC0-1.0 |
| wm-0045 | [Old bridge on the Rio Torretta (2024).jpg](https://commons.wikimedia.org/wiki/File:Old_bridge_on_the_Rio_Torretta_(2024).jpg) | Schwitzenburgenstein | CC0-1.0 |
| wm-0046 | [St. Basil Church, Carrick, tower, 2020-12-10, 01.jpg](https://commons.wikimedia.org/wiki/File:St._Basil_Church,_Carrick,_tower,_2020-12-10,_01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0047 | [2020 08 Bojnice castle 2.jpg](https://commons.wikimedia.org/wiki/File:2020_08_Bojnice_castle_2.jpg) | Qasinka | CC0-1.0 |
| wm-0048 | [ChicagoHarborLighthouseJuly2019.jpg](https://commons.wikimedia.org/wiki/File:ChicagoHarborLighthouseJuly2019.jpg) | JohnDziak | CC0-1.0 |
| wm-0049 | [Fountain in Public Square, Watertown, New York.jpg](https://commons.wikimedia.org/wiki/File:Fountain_in_Public_Square,_Watertown,_New_York.jpg) | Lallint | CC0-1.0 |
| wm-0050 | [Kehra railway bridge 2019.jpg](https://commons.wikimedia.org/wiki/File:Kehra_railway_bridge_2019.jpg) | Zmobbie | CC0-1.0 |
| wm-0051 | [Belle Tout Lighthouse, June 2020 01.jpg](https://commons.wikimedia.org/wiki/File:Belle_Tout_Lighthouse,_June_2020_01.jpg) | Poliphilo | CC0-1.0 |
| wm-0052 | [Bear Lake, August 2024.jpg](https://commons.wikimedia.org/wiki/File:Bear_Lake,_August_2024.jpg) | AutumnNY | CC0-1.0 |
| wm-0053 | [Secret Caverns Waterfall- June 2024.jpg](https://commons.wikimedia.org/wiki/File:Secret_Caverns_Waterfall-_June_2024.jpg) | FossilDS | CC0-1.0 |
| wm-0054 | [2023 Hażlach path to Borgońka.jpg](https://commons.wikimedia.org/wiki/File:2023_Ha%C5%BClach_path_to_Borgo%C5%84ka.jpg) | Qasinka | CC0-1.0 |
| wm-0055 | [2017-01-20 Blick auf Großrinderfeld im Winter - 8.jpg](https://commons.wikimedia.org/wiki/File:2017-01-20_Blick_auf_Gro%C3%9Frinderfeld_im_Winter_-_8.jpg) | Triplec85 | CC0-1.0 |
| wm-0056 | [Autumn colours of leaves at Koishikawa Kourakuen IMG 3863.jpg](https://commons.wikimedia.org/wiki/File:Autumn_colours_of_leaves_at_Koishikawa_Kourakuen_IMG_3863.jpg) | Soseipapa | CC0-1.0 |
| wm-0057 | [Mountain landscape (21827581301).jpg](https://commons.wikimedia.org/wiki/File:Mountain_landscape_(21827581301).jpg) | StockyPics | CC0-1.0 |
| wm-0058 | [Blue trail blaze Anthony's Nose NY.jpg](https://commons.wikimedia.org/wiki/File:Blue_trail_blaze_Anthony%27s_Nose_NY.jpg) | Reconrabbit | CC0-1.0 |
| wm-0059 | [Foxglove on meadow, Eschenhahn.jpg](https://commons.wikimedia.org/wiki/File:Foxglove_on_meadow,_Eschenhahn.jpg) | Gerda Arendt | CC0-1.0 |
| wm-0060 | [2021 Bukowieckie Lake (Skoki).jpg](https://commons.wikimedia.org/wiki/File:2021_Bukowieckie_Lake_(Skoki).jpg) | Qasinka | CC0-1.0 |
| wm-0061 | [Ostia Sea Beach in 2012.01.jpg](https://commons.wikimedia.org/wiki/File:Ostia_Sea_Beach_in_2012.01.jpg) | CAPTAIN RAJU | CC0-1.0 |
| wm-0062 | [Small forest path off Frager Road in Kent, Washington.jpg](https://commons.wikimedia.org/wiki/File:Small_forest_path_off_Frager_Road_in_Kent,_Washington.jpg) | Roc0ast3r | CC0-1.0 |
| wm-0063 | [Autumn leaves came unusally late this year (December 11 2021).jpg](https://commons.wikimedia.org/wiki/File:Autumn_leaves_came_unusally_late_this_year_(December_11_2021).jpg) | Syced | CC0-1.0 |
| wm-0064 | [Mountain Glacier Landscape (from AvoPix).jpg](https://commons.wikimedia.org/wiki/File:Mountain_Glacier_Landscape_(from_AvoPix).jpg) | Unknown @ AvoPix.com | CC0-1.0 |
| wm-0065 | [Guadamía river and beach.jpg](https://commons.wikimedia.org/wiki/File:Guadam%C3%ADa_river_and_beach.jpg) | BBdot | CC0-1.0 |
| wm-0066 | [Meadow with thistles and butterflies, Ennerich.jpg](https://commons.wikimedia.org/wiki/File:Meadow_with_thistles_and_butterflies,_Ennerich.jpg) | Gerda Arendt | CC0-1.0 |
| wm-0067 | [Cascade de la Pissarde.jpg](https://commons.wikimedia.org/wiki/File:Cascade_de_la_Pissarde.jpg) | Wisi eu | CC0-1.0 |
| wm-0068 | [Forest path during autumn.jpg](https://commons.wikimedia.org/wiki/File:Forest_path_during_autumn.jpg) | Paxxen | CC0-1.0 |
| wm-0069 | [Ice on river bank.jpg](https://commons.wikimedia.org/wiki/File:Ice_on_river_bank.jpg) | Terry.grignon | CC0-1.0 |
| wm-0070 | [Cat sleeping AUA (June 2023).JPG](https://commons.wikimedia.org/wiki/File:Cat_sleeping_AUA_(June_2023).JPG) | Benoît Prieur | CC0-1.0 |
| wm-0071 | ['Radhe' the pet cat of Worli fish marke in Mumbai..(Wednesday 14-3-2012).JPG](https://commons.wikimedia.org/wiki/File:%27Radhe%27_the_pet_cat_of_Worli_fish_marke_in_Mumbai..(Wednesday_14-3-2012).JPG) | Rudolph.A.furtado | CC0-1.0 |
| wm-0072 | [Rear view of a dog in the Philippines (9611Photos taken during 2020 coronavirus pandemic 03).jpg](https://commons.wikimedia.org/wiki/File:Rear_view_of_a_dog_in_the_Philippines_(9611Photos_taken_during_2020_coronavirus_pandemic_03).jpg) | Judgefloro | CC0-1.0 |
| wm-0073 | [Sleeping cat in Capri, Italy 2026-05-29.jpg](https://commons.wikimedia.org/wiki/File:Sleeping_cat_in_Capri,_Italy_2026-05-29.jpg) | GuiltyGearFan37 | CC0-1.0 |
| wm-0074 | [Dog Sleeping.jpg](https://commons.wikimedia.org/wiki/File:Dog_Sleeping.jpg) | Ritchde | CC0-1.0 |
| wm-0075 | [Stray cat sleeping on the street of Colombo 2018-03-17.jpg](https://commons.wikimedia.org/wiki/File:Stray_cat_sleeping_on_the_street_of_Colombo_2018-03-17.jpg) | FaysaLBinDaruL | CC0-1.0 |
| wm-0076 | [SZ 深圳 Shenzhen 寶安 BaoAn 萬豐大仟里 MaxLand Mall shop 屋虎貓館 Woo Hoo Pet Cat House February 2025 R12S white.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E5%AF%B6%E5%AE%89_BaoAn_%E8%90%AC%E8%B1%90%E5%A4%A7%E4%BB%9F%E9%87%8C_MaxLand_Mall_shop_%E5%B1%8B%E8%99%8E%E8%B2%93%E9%A4%A8_Woo_Hoo_Pet_Cat_House_February_2025_R12S_white.jpg) | LAAePSts Lusnsaz WHA | CC0-1.0 |
| wm-0077 | [Dog on a beach.jpg](https://commons.wikimedia.org/wiki/File:Dog_on_a_beach.jpg) | Unbeatable101 | CC0-1.0 |
| wm-0078 | [Cat matahari sleeping with one eye open.Bizarre..jpg](https://commons.wikimedia.org/wiki/File:Cat_matahari_sleeping_with_one_eye_open.Bizarre..jpg) | Rudolph.A.furtado | CC0-1.0 |
| wm-0079 | [White and gray silverpoint domestic cat lying down in basket.jpg](https://commons.wikimedia.org/wiki/File:White_and_gray_silverpoint_domestic_cat_lying_down_in_basket.jpg) | Poryden | CC0-1.0 |
| wm-0080 | [Dog outside.jpg](https://commons.wikimedia.org/wiki/File:Dog_outside.jpg) | Rruunnaa | CC0-1.0 |
| wm-0081 | [Cat - Moomin.jpg](https://commons.wikimedia.org/wiki/File:Cat_-_Moomin.jpg) | Tetizeraz | CC0-1.0 |
| wm-0082 | [Cat chews on bottle.jpg](https://commons.wikimedia.org/wiki/File:Cat_chews_on_bottle.jpg) | Punker1999 | CC0-1.0 |
| wm-0083 | [Pūriri unripe fruit 20250702 130645.jpg](https://commons.wikimedia.org/wiki/File:P%C5%ABriri_unripe_fruit_20250702_130645.jpg) | Prosperosity | CC0-1.0 |
| wm-0084 | [Pūriri flower 20250702 130801.jpg](https://commons.wikimedia.org/wiki/File:P%C5%ABriri_flower_20250702_130801.jpg) | Prosperosity | CC0-1.0 |
| wm-0085 | [Carex flagellifera 'Toffee Twist' - Lyman Plant House, Smith College - DSC04215.JPG](https://commons.wikimedia.org/wiki/File:Carex_flagellifera_%27Toffee_Twist%27_-_Lyman_Plant_House,_Smith_College_-_DSC04215.JPG) | Daderot | CC0-1.0 |
| wm-0086 | [Portland International Rose Test Garden - HCP - October 15, 2022 - 008.jpg](https://commons.wikimedia.org/wiki/File:Portland_International_Rose_Test_Garden_-_HCP_-_October_15,_2022_-_008.jpg) | Vulturesong | CC0-1.0 |
| wm-0087 | [Washingtonia x filibusta small 01.jpg](https://commons.wikimedia.org/wiki/File:Washingtonia_x_filibusta_small_01.jpg) | B137 | CC0-1.0 |
| wm-0088 | [Iowa Tulip.jpg](https://commons.wikimedia.org/wiki/File:Iowa_Tulip.jpg) | Maatpublishing | CC0-1.0 |
| wm-0089 | [Portland International Rose Test Garden - HCP - October 15, 2022 - 009.jpg](https://commons.wikimedia.org/wiki/File:Portland_International_Rose_Test_Garden_-_HCP_-_October_15,_2022_-_009.jpg) | Vulturesong | CC0-1.0 |
| wm-0090 | [Beavertail Cactus Flower Crazy (2547547776).jpg](https://commons.wikimedia.org/wiki/File:Beavertail_Cactus_Flower_Crazy_(2547547776).jpg) | cogdogblog | CC0-1.0 |
| wm-0091 | [Aglaonema simplex - Lyman Plant House, Smith College - DSC04243.JPG](https://commons.wikimedia.org/wiki/File:Aglaonema_simplex_-_Lyman_Plant_House,_Smith_College_-_DSC04243.JPG) | Daderot | CC0-1.0 |
| wm-0092 | [Portland International Rose Test Garden - HCP - October 15, 2022 - 013.jpg](https://commons.wikimedia.org/wiki/File:Portland_International_Rose_Test_Garden_-_HCP_-_October_15,_2022_-_013.jpg) | Vulturesong | CC0-1.0 |
| wm-0093 | [観葉植物.jpg](https://commons.wikimedia.org/wiki/File:%E8%A6%B3%E8%91%89%E6%A4%8D%E7%89%A9.jpg) | 椿七十郎 | CC0-1.0 |
| wm-0094 | [Ostia Sea Beach in 2012.04.jpg](https://commons.wikimedia.org/wiki/File:Ostia_Sea_Beach_in_2012.04.jpg) | CAPTAIN RAJU | CC0-1.0 |
| wm-0095 | [Aruba — Catamaran Sailing at Sunset — 2023.jpg](https://commons.wikimedia.org/wiki/File:Aruba_%E2%80%94_Catamaran_Sailing_at_Sunset_%E2%80%94_2023.jpg) | Rarends297 | CC0-1.0 |
| wm-0096 | [2024-09-17 near-equinoctial sunrise in Chicago, Illinois viewed along Jackson Boulevard 02.jpg](https://commons.wikimedia.org/wiki/File:2024-09-17_near-equinoctial_sunrise_in_Chicago,_Illinois_viewed_along_Jackson_Boulevard_02.jpg) | Dan Leonard | CC0-1.0 |
| wm-0097 | [IMG Clouds sky.jpg](https://commons.wikimedia.org/wiki/File:IMG_Clouds_sky.jpg) | Liyan Alsaideh14 | CC0-1.0 |
| wm-0098 | [Streetcar and rainbow, Beechview, 2023-01-25, 01.jpg](https://commons.wikimedia.org/wiki/File:Streetcar_and_rainbow,_Beechview,_2023-01-25,_01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0099 | [20200309 Night sky.jpg](https://commons.wikimedia.org/wiki/File:20200309_Night_sky.jpg) | Gb89.2 | CC0-1.0 |
| wm-0100 | [Sunset over Beechview, 2021-09-25, 01.jpg](https://commons.wikimedia.org/wiki/File:Sunset_over_Beechview,_2021-09-25,_01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0101 | [Evening sky 2024.jpg](https://commons.wikimedia.org/wiki/File:Evening_sky_2024.jpg) | Swathi sri srinivasa raghavan | CC0-1.0 |
| wm-0102 | [Waxing half moon over Brofjorden 2.jpg](https://commons.wikimedia.org/wiki/File:Waxing_half_moon_over_Brofjorden_2.jpg) | W.carter | CC0-1.0 |
| wm-0103 | [Sunset clouds over Beechview,2022-12ť8,01.jpg](https://commons.wikimedia.org/wiki/File:Sunset_clouds_over_Beechview,2022-12%C5%A58,01.jpg) | Cbaile19 | CC0-1.0 |
| wm-0104 | [Moon-sky night.jpg](https://commons.wikimedia.org/wiki/File:Moon-sky_night.jpg) | ChahadiQw | CC0-1.0 |
| wm-0105 | [Sunset bright, sep 11 2026.jpg](https://commons.wikimedia.org/wiki/File:Sunset_bright,_sep_11_2026.jpg) | Logan M Diel | CC0-1.0 |
| wm-0106 | [Ole Miss vs Penn State, 2023 Peach Bowl, Mercedes-Benz Stadium, Atlanta.jpg](https://commons.wikimedia.org/wiki/File:Ole_Miss_vs_Penn_State,_2023_Peach_Bowl,_Mercedes-Benz_Stadium,_Atlanta.jpg) | Marycollinsc | CC0-1.0 |
| wm-0107 | [Basketball Court-2024.jpg](https://commons.wikimedia.org/wiki/File:Basketball_Court-2024.jpg) | Louis lnak1410 | CC0-1.0 |
| wm-0108 | [Epsom Tennis Club (July 2021).jpg](https://commons.wikimedia.org/wiki/File:Epsom_Tennis_Club_(July_2021).jpg) | Mertbiol | CC0-1.0 |
| wm-0109 | [Toyokawa City Athletic Field (2017-05-28) 2.jpg](https://commons.wikimedia.org/wiki/File:Toyokawa_City_Athletic_Field_(2017-05-28)_2.jpg) | Lombroso | CC0-1.0 |
| wm-0110 | [Ball State Cardinals at Northwestern Wildcats football view from north endzone main concourse (2026-10-10).jpg](https://commons.wikimedia.org/wiki/File:Ball_State_Cardinals_at_Northwestern_Wildcats_football_view_from_north_endzone_main_concourse_(2026-10-10).jpg) | Candycaneman | CC0-1.0 |
| wm-0111 | [DJ Sherrington Park skate bowl Blunder Rd and Inala Ave Inala P1380679.jpg](https://commons.wikimedia.org/wiki/File:DJ_Sherrington_Park_skate_bowl_Blunder_Rd_and_Inala_Ave_Inala_P1380679.jpg) | John Robert McPherson | CC0-1.0 |
| wm-0112 | [Basketball court, Mid Street Recreation Ground, Nutfield, Surrey - May 2026 - 02.jpg](https://commons.wikimedia.org/wiki/File:Basketball_court,_Mid_Street_Recreation_Ground,_Nutfield,_Surrey_-_May_2026_-_02.jpg) | Mertbiol | CC0-1.0 |
| wm-0113 | [Dyke Road Park Tennis Courts 2023-06-03.jpg](https://commons.wikimedia.org/wiki/File:Dyke_Road_Park_Tennis_Courts_2023-06-03.jpg) | Andy Li | CC0-1.0 |
| wm-0114 | [Market in Zagreb.jpg](https://commons.wikimedia.org/wiki/File:Market_in_Zagreb.jpg) | HHRIA123 | CC0-1.0 |
| wm-0115 | [20200925-dutch-alley-1930s.jpg](https://commons.wikimedia.org/wiki/File:20200925-dutch-alley-1930s.jpg) | Jeroen Hoek | CC0-1.0 |
| wm-0116 | [No parking sign Khorenatsi street, Yerevan (May 2018).jpg](https://commons.wikimedia.org/wiki/File:No_parking_sign_Khorenatsi_street,_Yerevan_(May_2018).jpg) | Benoît Prieur | CC0-1.0 |
| wm-0117 | [Traffic light sign 20240322 130206.jpg](https://commons.wikimedia.org/wiki/File:Traffic_light_sign_20240322_130206.jpg) | Taufik | CC0-1.0 |
| wm-0118 | [CARTA bus stop - October 2025 - Sarah Stierch.jpg](https://commons.wikimedia.org/wiki/File:CARTA_bus_stop_-_October_2025_-_Sarah_Stierch.jpg) | Missvain | CC0-1.0 |
| wm-0119 | [Disabled pedestrian crossing sign 20250615 161240.jpg](https://commons.wikimedia.org/wiki/File:Disabled_pedestrian_crossing_sign_20250615_161240.jpg) | Taufik | CC0-1.0 |
| wm-0120 | [Alley of trees decorated with Christmas lights (2022-12-31) 2.jpg](https://commons.wikimedia.org/wiki/File:Alley_of_trees_decorated_with_Christmas_lights_(2022-12-31)_2.jpg) | Almanta | CC0-1.0 |
| wm-0121 | [שלטי חניה בתשלום ברחוב רוגוזין, רובע ד' באשדוד, ינואר 2025.jpg](https://commons.wikimedia.org/wiki/File:%D7%A9%D7%9C%D7%98%D7%99_%D7%97%D7%A0%D7%99%D7%94_%D7%91%D7%AA%D7%A9%D7%9C%D7%95%D7%9D_%D7%91%D7%A8%D7%97%D7%95%D7%91_%D7%A8%D7%95%D7%92%D7%95%D7%96%D7%99%D7%9F,_%D7%A8%D7%95%D7%91%D7%A2_%D7%93%27_%D7%91%D7%90%D7%A9%D7%93%D7%95%D7%93,_%D7%99%D7%A0%D7%95%D7%90%D7%A8_2025.jpg) | מקף־עברי | CC0-1.0 |
| wm-0122 | [Crossing marked with a traffic sign 20190517 184744 HDR.jpg](https://commons.wikimedia.org/wiki/File:Crossing_marked_with_a_traffic_sign_20190517_184744_HDR.jpg) | Mateusz Konieczny | CC0-1.0 |
| wm-0123 | [20200806 164500 things places in south korea IMG 9609.jpg](https://commons.wikimedia.org/wiki/File:20200806_164500_things_places_in_south_korea_IMG_9609.jpg) | Choi Kwang-mo | CC0-1.0 |
| wm-0124 | [Bus stop at Samad Vurgun.jpg](https://commons.wikimedia.org/wiki/File:Bus_stop_at_Samad_Vurgun.jpg) | rwp | CC0-1.0 |
| wm-0125 | [Refurbished Musselburgh Rise pedestrian crossing, 29 Jul 2026.jpg](https://commons.wikimedia.org/wiki/File:Refurbished_Musselburgh_Rise_pedestrian_crossing,_29_Jul_2026.jpg) | Andykatib | CC0-1.0 |
| wm-0126 | [Berlin Reinickendorf frog graffiti on house wall 20260819 02.jpg](https://commons.wikimedia.org/wiki/File:Berlin_Reinickendorf_frog_graffiti_on_house_wall_20260819_02.jpg) | NutzerAusBerlin | CC0-1.0 |
| wm-0127 | [No parking sign cutcot pulilan 20241205jwilz.jpg](https://commons.wikimedia.org/wiki/File:No_parking_sign_cutcot_pulilan_20241205jwilz.jpg) | JWilz12345 | CC0-1.0 |
| wm-0128 | [Bücherschrank Baldham Marktplatz 2025-03-24.jpg](https://commons.wikimedia.org/wiki/File:B%C3%BCcherschrank_Baldham_Marktplatz_2025-03-24.jpg) | Felix Edelmann | CC0-1.0 |
| wm-0129 | [SZ 深圳 Shenzhen 龍華 Longhua 旺民路 Wangmin Road park yellow public sharing bicycle parking February 2025 R12S 02.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E9%BE%8D%E8%8F%AF_Longhua_%E6%97%BA%E6%B0%91%E8%B7%AF_Wangmin_Road_park_yellow_public_sharing_bicycle_parking_February_2025_R12S_02.jpg) | ALB 302 AOE woapsing | CC0-1.0 |
| wm-0130 | [Street views in Hitech City (55904).jpg](https://commons.wikimedia.org/wiki/File:Street_views_in_Hitech_City_(55904).jpg) | Syced | CC0-1.0 |
| wm-0131 | [Bicycles Mannerheim Park Oulu 20210209.jpg](https://commons.wikimedia.org/wiki/File:Bicycles_Mannerheim_Park_Oulu_20210209.jpg) | Estormiz | CC0-1.0 |
| wm-0132 | [Moscow, Mira Prospect, bikes May 2025 04.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_Mira_Prospect,_bikes_May_2025_04.jpg) | Retired electrician | CC0-1.0 |
| wm-0133 | [Darnall station car park, June 2021.jpg](https://commons.wikimedia.org/wiki/File:Darnall_station_car_park,_June_2021.jpg) | TheFrog001 | CC0-1.0 |
| wm-0134 | [Kuzuryuko Station platform 20120909.jpg](https://commons.wikimedia.org/wiki/File:Kuzuryuko_Station_platform_20120909.jpg) | Fumon1987a | CC0-1.0 |
| wm-0135 | [Moscow, small motorcycle, May 2026 01.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_small_motorcycle,_May_2026_01.jpg) | Retired electrician | CC0-1.0 |
| wm-0136 | [Moscow, Kaluzhskaya Ploshchad tram loop June 2022 07.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_Kaluzhskaya_Ploshchad_tram_loop_June_2022_07.jpg) | Retired electrician | CC0-1.0 |
| wm-0137 | [Moscow, Velobike electro-scooter, July 2025 03.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_Velobike_electro-scooter,_July_2025_03.jpg) | Retired electrician | CC0-1.0 |
| wm-0138 | [Ouluhalli Car Park 20250216.jpg](https://commons.wikimedia.org/wiki/File:Ouluhalli_Car_Park_20250216.jpg) | Estormiz | CC0-1.0 |
| wm-0139 | [Moscow, BMW motorcycle red, June 2026 01.jpg](https://commons.wikimedia.org/wiki/File:Moscow,_BMW_motorcycle_red,_June_2026_01.jpg) | Retired electrician | CC0-1.0 |
| wm-0140 | [York Inset Scooter Club Show and Shine 2025 02.jpg](https://commons.wikimedia.org/wiki/File:York_Inset_Scooter_Club_Show_and_Shine_2025_02.jpg) | Malcolmxl5 | CC0-1.0 |


## Round 2 (2026-11-20): 154 more photos

304 entries now: 83 from the WordPress Photo Directory (`ov-0001`..`ov-0083`) and 71 more from Wikimedia Commons (`wm-0141`..`wm-0211`), all CC0. New categories: `travel`, `event`, `shopping`, `selfie_like_no_face`. 45 of the 304 entries have `has_people: true`; the generator does not use them.

Downscaled files: their `url` serves the original, so a download is verified against `sha256_original`; the stored copy's `sha256` matches a file imported with `photos import`.

The two round-2 parts' own notes follow.

## Part 'openverse': sources

Accessed 2026-11-20. 83 photos (`ov-0001`..`ov-0083`), all from the **WordPress Photo Directory** (wordpress.org/photos), licence CC0-1.0. No Wikimedia Commons files (another part covers Commons). Entries are in `manifest.part-openverse.yaml`.

## How the photos were found

- Intended discovery index: the Openverse API (`api.openverse.org/v1/images/`, `license=cc0,pdm`, anonymous: 20 req/min, 200 req/day). During this run it was largely over capacity: about half of all calls returned HTTP 500/503/504 ("Search is over capacity"); 47 queries succeeded. 
- **Flickr (via Openverse) was abandoned.** Licences verified fine on the Flickr photo pages (photo model `license` 9 = CC0, 10 = PDM), but the image CDN `live.staticflickr.com` answers HTTP 403 to the required User-Agent `SandroidResearchBot/0.2 (research; no contact)` (any UA containing "Bot"). We did not change the User-Agent to get around that block, so no Flickr file was downloaded.
- **StockSnap** (via Openverse) sits behind a Cloudflare browser challenge: its licence page can't be verified, so it was skipped. **Rawpixel** only offers 1024 px images to anonymous clients (too small).
- **WordPress Photo Directory** (an Openverse source, `source=wordpress`): Openverse returned only 0 to 20 hits per query and mostly timed out, so most candidates came straight from the directory's public REST API (`wordpress.org/photos/wp-json/wp/v2/photos?search=..&_embed=wp:featuredmedia`, plus category filters such as Athletics), 92 queries. 3 of the 83 kept photos were also returned by Openverse.
- Pre-filter: long side >= 1600 px; aspect 4:3 or 16:9 (either orientation, ratio 1.30-1.36 or 1.74-1.80); dropped the directory's "People" category (except for events) and descriptions that mention faces, people, statues, museums, logos etc. That left 1,854 candidates, from which 280 were picked across categories (round-robin over queries, keyword had to be in the description) and reviewed by eye on contact sheets. 83 were kept; the rest were off-topic (fuzzy search), artworks, statues or idols, logo-heavy shelves, ad posters with faces, near-identical views, or unclear country/landmark identity.
- Client: User-Agent `SandroidResearchBot/0.2 (research; no contact)`, at most 1 request every 1.2-1.5 s to wordpress.org/pd.w.org and every 4.5 s to Openverse. Retry-After was honoured; wordpress.org never returned a 429.

## Licence verification

For every kept photo the original page `https://wordpress.org/photos/photo/<slug>/` was fetched, and its schema.org `ImageObject` JSON-LD had to state `"license": "https://creativecommons.org/publicdomain/zero/1.0/"`. The visible text "CC0 licensed photo by <author>" had to be present too. `author` is the JSON-LD `creator.name` (the contributor's directory name). The file came from the JSON-LD `contentUrl` (the original upload on pd.w.org). The directory states that contributors submit their original work under CC0, and volunteers moderate the submissions. No PDM files ended up in this part.

## Processing

Same as the main part: JPEG SOI check and Pillow `verify()`; `original_had_exif`/`original_had_gps` read from the original (52 had EXIF, 27 had GPS). Originals whose long side is > 3200 px (78 of 83) were downscaled in a copy to 3000 px long side (Pillow LANCZOS, JPEG q90, original EXIF + ICC carried over, raw pixels not rotated, so EXIF Orientation still applies). `*_original` fields describe the pd.w.org original. Duplicate check: perceptual hash (imagehash pHash) distance <= 6 against all 150 existing files in `files/` and within this part found no matches. sha256s are unique. When this part was written, `files/` held no files from the other new part, so cross-part dedupe still has to run at merge time. Total size: 127.7 MB.

Flags: `has_people: true` means a hand, feet, legs or a distant crowd seen from behind are visible (19 files); no identifiable face. `country` is set where a known landmark, script or branding ties the photo to one country (15 files). Readable text was checked: the ticket, menu, whiteboards and recipe card show business names, prices and recipe text only, with no personal data.

## Counts

| category | n |
|---|---|
| sport | 10 |
| landmark_generic | 9 |
| document_like | 9 |
| interior | 9 |
| pet | 9 |
| food | 8 |
| shopping (new) | 8 |
| travel (new) | 8 |
| selfie_like_no_face (new) | 7 |
| event (new) | 6 |

## Per-file attribution (CC0 needs none; recorded anyway)

| id | WordPress photo | author | category | licence |
|---|---|---|---|---|
| ov-0001 | [4796aeacc4](https://wordpress.org/photos/photo/4796aeacc4/) | madelinecorderoruiz | sport | CC0-1.0 |
| ov-0002 | [7096aaebe3](https://wordpress.org/photos/photo/7096aaebe3/) | Vishnu Chandra | sport | CC0-1.0 |
| ov-0003 | [816a9e93ef](https://wordpress.org/photos/photo/816a9e93ef/) | diaz827 | sport | CC0-1.0 |
| ov-0004 | [9066ab1611](https://wordpress.org/photos/photo/9066ab1611/) | Marcos Cernadas Valiño | sport | CC0-1.0 |
| ov-0005 | [13665ac8d8](https://wordpress.org/photos/photo/13665ac8d8/) | Heru Irawan | sport | CC0-1.0 |
| ov-0006 | [2386aaef8c](https://wordpress.org/photos/photo/2386aaef8c/) | alejandrorubin02 | sport | CC0-1.0 |
| ov-0007 | [7396a27d86](https://wordpress.org/photos/photo/7396a27d86/) | Rashed Hossain | sport | CC0-1.0 |
| ov-0008 | [5796a66ecf](https://wordpress.org/photos/photo/5796a66ecf/) | marbizu | sport | CC0-1.0 |
| ov-0009 | [6896a27b7d](https://wordpress.org/photos/photo/6896a27b7d/) | Rashed Hossain | sport | CC0-1.0 |
| ov-0010 | [73569d3f38](https://wordpress.org/photos/photo/73569d3f38/) | Hiral Solanki | sport | CC0-1.0 |
| ov-0011 | [5456a96eac](https://wordpress.org/photos/photo/5456a96eac/) | Iker Santos Insua | landmark_generic | CC0-1.0 |
| ov-0012 | [9516afa05c](https://wordpress.org/photos/photo/9516afa05c/) | xbullscm | landmark_generic | CC0-1.0 |
| ov-0013 | [8346af2af2](https://wordpress.org/photos/photo/8346af2af2/) | xbullscm | landmark_generic | CC0-1.0 |
| ov-0014 | [5446aecdf3](https://wordpress.org/photos/photo/5446aecdf3/) | joseandres712 | landmark_generic | CC0-1.0 |
| ov-0015 | [7666afdd06](https://wordpress.org/photos/photo/7666afdd06/) | ogarcia04 | landmark_generic | CC0-1.0 |
| ov-0016 | [8466ad4a56](https://wordpress.org/photos/photo/8466ad4a56/) | Nahuai Badiola | landmark_generic | CC0-1.0 |
| ov-0017 | [6906906198](https://wordpress.org/photos/photo/6906906198/) | Abdalsalaam Halawa | landmark_generic | CC0-1.0 |
| ov-0018 | [2876afe6fc](https://wordpress.org/photos/photo/2876afe6fc/) | joseandres712 | landmark_generic | CC0-1.0 |
| ov-0019 | [3106a652ad](https://wordpress.org/photos/photo/3106a652ad/) | upekar99 | landmark_generic | CC0-1.0 |
| ov-0020 | [5896ae47c4](https://wordpress.org/photos/photo/5896ae47c4/) | Moses Cursor Ssebunya | document_like | CC0-1.0 |
| ov-0021 | [83162fe473](https://wordpress.org/photos/photo/83162fe473/) | redIT | document_like | CC0-1.0 |
| ov-0022 | [4136a6e6ff](https://wordpress.org/photos/photo/4136a6e6ff/) | gabrielloayza | document_like | CC0-1.0 |
| ov-0023 | [54967d7b4e](https://wordpress.org/photos/photo/54967d7b4e/) | Yam B Chhetri | document_like | CC0-1.0 |
| ov-0024 | [3746a294c9](https://wordpress.org/photos/photo/3746a294c9/) | appealdahal | document_like | CC0-1.0 |
| ov-0025 | [8116a1d3f1](https://wordpress.org/photos/photo/8116a1d3f1/) | Rashed Hossain | document_like | CC0-1.0 |
| ov-0026 | [964672a81e](https://wordpress.org/photos/photo/964672a81e/) | ams67 | document_like | CC0-1.0 |
| ov-0027 | [3336a0d99b](https://wordpress.org/photos/photo/3336a0d99b/) | shirishpoudel07 | document_like | CC0-1.0 |
| ov-0028 | [8326983f3e](https://wordpress.org/photos/photo/8326983f3e/) | sweekar7 | document_like | CC0-1.0 |
| ov-0029 | [1046a1ef01](https://wordpress.org/photos/photo/1046a1ef01/) | WPKitchen | interior | CC0-1.0 |
| ov-0030 | [1536566d31](https://wordpress.org/photos/photo/1536566d31/) | 渡邉厚夫(たいちょ渡邉) | interior | CC0-1.0 |
| ov-0031 | [226ae161ca](https://wordpress.org/photos/photo/226ae161ca/) | Carlos Moreno | interior | CC0-1.0 |
| ov-0032 | [8756ae137b](https://wordpress.org/photos/photo/8756ae137b/) | Carlos Moreno | interior | CC0-1.0 |
| ov-0033 | [8126a90fc8](https://wordpress.org/photos/photo/8126a90fc8/) | louise18 | interior | CC0-1.0 |
| ov-0034 | [1276a00258](https://wordpress.org/photos/photo/1276a00258/) | Pritam Sonone | interior | CC0-1.0 |
| ov-0035 | [4586ae0192](https://wordpress.org/photos/photo/4586ae0192/) | Carlos Moreno | interior | CC0-1.0 |
| ov-0036 | [76768f70bd](https://wordpress.org/photos/photo/76768f70bd/) | Shifat Jaman | interior | CC0-1.0 |
| ov-0037 | [436abfc19d](https://wordpress.org/photos/photo/436abfc19d/) | Rashed Hossain | interior | CC0-1.0 |
| ov-0038 | [2316734aba](https://wordpress.org/photos/photo/2316734aba/) | David Allsop | pet | CC0-1.0 |
| ov-0039 | [7076aed492](https://wordpress.org/photos/photo/7076aed492/) | Ricardo Ulate Alpizar | pet | CC0-1.0 |
| ov-0040 | [606a217e6b](https://wordpress.org/photos/photo/606a217e6b/) | karodel | pet | CC0-1.0 |
| ov-0041 | [596aebb5a4](https://wordpress.org/photos/photo/596aebb5a4/) | Ricardo Ulate Alpizar | pet | CC0-1.0 |
| ov-0042 | [6136afe122](https://wordpress.org/photos/photo/6136afe122/) | Emmanuel Salazar Arias. | pet | CC0-1.0 |
| ov-0043 | [416afcfc90](https://wordpress.org/photos/photo/416afcfc90/) | Francisco Mora | pet | CC0-1.0 |
| ov-0044 | [4646afe11d](https://wordpress.org/photos/photo/4646afe11d/) | Emmanuel Salazar Arias. | pet | CC0-1.0 |
| ov-0045 | [1886af91bb](https://wordpress.org/photos/photo/1886af91bb/) | brodiex1926 | pet | CC0-1.0 |
| ov-0046 | [1856aa2d19](https://wordpress.org/photos/photo/1856aa2d19/) | diaz827 | pet | CC0-1.0 |
| ov-0047 | [9936afe897](https://wordpress.org/photos/photo/9936afe897/) | Bigul Malayi | food | CC0-1.0 |
| ov-0048 | [7666aec7b0](https://wordpress.org/photos/photo/7666aec7b0/) | Swetha B Chandran | food | CC0-1.0 |
| ov-0049 | [3566ae07f8](https://wordpress.org/photos/photo/3566ae07f8/) | Anushila Basnet | food | CC0-1.0 |
| ov-0050 | [2626aed535](https://wordpress.org/photos/photo/2626aed535/) | genesisoba | food | CC0-1.0 |
| ov-0051 | [7806afc053](https://wordpress.org/photos/photo/7806afc053/) | genesisoba | food | CC0-1.0 |
| ov-0052 | [2836aff948](https://wordpress.org/photos/photo/2836aff948/) | genrodri04 | food | CC0-1.0 |
| ov-0053 | [386adf000e](https://wordpress.org/photos/photo/386adf000e/) | mriduljp | food | CC0-1.0 |
| ov-0054 | [65869d9aed](https://wordpress.org/photos/photo/65869d9aed/) | Bigul Malayi | food | CC0-1.0 |
| ov-0055 | [36269f58f5](https://wordpress.org/photos/photo/36269f58f5/) | Vishnu Chandra | selfie_like_no_face | CC0-1.0 |
| ov-0056 | [50068d67f2](https://wordpress.org/photos/photo/50068d67f2/) | shirishpoudel07 | selfie_like_no_face | CC0-1.0 |
| ov-0057 | [836acc9e82](https://wordpress.org/photos/photo/836acc9e82/) | Milan Khanal | selfie_like_no_face | CC0-1.0 |
| ov-0058 | [4956a12ad8](https://wordpress.org/photos/photo/4956a12ad8/) | Rashed Hossain | selfie_like_no_face | CC0-1.0 |
| ov-0059 | [85268c2934](https://wordpress.org/photos/photo/85268c2934/) | shirishpoudel07 | selfie_like_no_face | CC0-1.0 |
| ov-0060 | [9106842737](https://wordpress.org/photos/photo/9106842737/) | Faisal Ahammad | selfie_like_no_face | CC0-1.0 |
| ov-0061 | [81268b068e](https://wordpress.org/photos/photo/81268b068e/) | Alina Kakshapati | selfie_like_no_face | CC0-1.0 |
| ov-0062 | [5716394f7e](https://wordpress.org/photos/photo/5716394f7e/) | Hans-Gerd Gerhards | event | CC0-1.0 |
| ov-0063 | [2966394f7b](https://wordpress.org/photos/photo/2966394f7b/) | Hans-Gerd Gerhards | event | CC0-1.0 |
| ov-0064 | [58068d2e5f](https://wordpress.org/photos/photo/58068d2e5f/) | robbinsathletics | event | CC0-1.0 |
| ov-0065 | [9676222e25](https://wordpress.org/photos/photo/9676222e25/) | Josh Pollock | event | CC0-1.0 |
| ov-0066 | [45261ff34c](https://wordpress.org/photos/photo/45261ff34c/) | Josh Pollock | event | CC0-1.0 |
| ov-0067 | [42365be422](https://wordpress.org/photos/photo/42365be422/) | arisepeter | event | CC0-1.0 |
| ov-0068 | [9826a217ec](https://wordpress.org/photos/photo/9826a217ec/) | karodel | shopping | CC0-1.0 |
| ov-0069 | [3566a0c55c](https://wordpress.org/photos/photo/3566a0c55c/) | Vishnu Chandra | shopping | CC0-1.0 |
| ov-0070 | [4556a46b77](https://wordpress.org/photos/photo/4556a46b77/) | Bigul Malayi | shopping | CC0-1.0 |
| ov-0071 | [26369e450b](https://wordpress.org/photos/photo/26369e450b/) | Rachel Cortés Torres | shopping | CC0-1.0 |
| ov-0072 | [53968ca5e1](https://wordpress.org/photos/photo/53968ca5e1/) | Faisal Ahammad | shopping | CC0-1.0 |
| ov-0073 | [94867cd3e8](https://wordpress.org/photos/photo/94867cd3e8/) | mitalid27 | shopping | CC0-1.0 |
| ov-0074 | [51465c5b63](https://wordpress.org/photos/photo/51465c5b63/) | Pooja Derashri | shopping | CC0-1.0 |
| ov-0075 | [6016a24535](https://wordpress.org/photos/photo/6016a24535/) | Bigul Malayi | shopping | CC0-1.0 |
| ov-0076 | [78646f6acd](https://wordpress.org/photos/photo/78646f6acd/) | Kuldip Chaudhary | travel | CC0-1.0 |
| ov-0077 | [4716a2a962](https://wordpress.org/photos/photo/4716a2a962/) | bezils | travel | CC0-1.0 |
| ov-0078 | [48068d22bb](https://wordpress.org/photos/photo/48068d22bb/) | Alina Kakshapati | travel | CC0-1.0 |
| ov-0079 | [6026ae015f](https://wordpress.org/photos/photo/6026ae015f/) | monicasolorzanosa | travel | CC0-1.0 |
| ov-0080 | [8906a29841](https://wordpress.org/photos/photo/8906a29841/) | Sarath AR | travel | CC0-1.0 |
| ov-0081 | [31966f35b2](https://wordpress.org/photos/photo/31966f35b2/) | Jeff Golenski | travel | CC0-1.0 |
| ov-0082 | [83468c16af](https://wordpress.org/photos/photo/83468c16af/) | shirishpoudel07 | travel | CC0-1.0 |
| ov-0083 | [35164d3695](https://wordpress.org/photos/photo/35164d3695/) | Corina Schedler | travel | CC0-1.0 |

## Part `commons2`: sources (Wikimedia Commons, round 2)

Accessed 2026-11-20 by agent `commons2`. Ids `wm-0141` onward; entries in `manifest.part-commons2.yaml`. Same pipeline and keys as round 1 (see `SOURCES.md`), with the changes below. No `original_exif_stripped` key.

## How the photos were found

- Source: Wikimedia Commons API (`https://commons.wikimedia.org/w/api.php`), `generator=search` in the File namespace, query `<terms> filetype:bitmap incategory:CC-zero -MET -museum -painting -drawing -illustration -portrait`, `prop=imageinfo&iiprop=url|size|sha1|mime|extmetadata`.
- 129 new search terms, none reused from round 1, weighted to the thin categories and the four new phone-typical ones: **sport**: stadium seats, football pitch grass, tennis racket, climbing wall, bowling alley, ski slope, golf course, sports hall, volleyball net, cycling road bike, soccer goal, table tennis, ice rink skating, dumbbells, baseball field, surfboard, kayak, running shoes, yoga mat, ski lift; **landmark_generic**: town hall, clock tower, windmill, obelisk, city gate, pier, old town square, cathedral facade, observation tower, aqueduct, harbour boats, skyline city, monastery, covered bridge; **document_like**: handwritten note, shopping list, boarding pass, train ticket, wall calendar, envelope letter, chalkboard menu, blackboard, cash receipt, parking ticket, price list, timetable, flipchart, notebook page, recipe card, restaurant bill, bus ticket, postcard, handwriting paper; **interior**: hotel room, dining room, bathroom, hallway corridor, home office, reading room, restaurant interior, staircase, apartment interior, classroom, waiting room, bar counter; **pet**: dog sofa, cat window, dog leash, rabbit, hamster, guinea pig, aquarium fish, budgerigar, cat playing, dog lying, cat on bed, dog walking; **food**: breakfast eggs, ramen, dumplings, tacos, croissant, pancakes, curry rice, sandwich, smoothie, wine glass, barbecue grill, donut, cookies, steak, street food, tea cup, cocktail drink; **selfie_like_no_face**: shoes feet, feet sand, hand holding cup, sneakers, hand holding, boots, feet water; **event**: fireworks, concert stage, christmas market, music festival, lantern festival, parade, light show, carnival; **shopping**: supermarket aisle, grocery store, market stall, bakery display, shopping mall, fruit stand, shop window, flea market, shopping cart; **travel**: airport terminal, train window, airplane window, hotel bed, railway station hall, suitcase, departure board, ferry deck, airport gate, train interior, luggage.
- 4,981 candidates kept by metadata: `image/jpeg`, long side >= 1600 px, aspect 1.2-2.25 (4:3 to ~20:9, portrait or landscape), `extmetadata.License == cc0` (every one is in Category:CC-zero, template `{{CC-zero}}`). A Public Domain Mark 1.0 file (`LicenseUrl` .../publicdomain/mark/1.0) would also have been accepted; none turned up (a `hastemplate:PDM-owner` probe found only scanned newspapers). Other PD templates were not accepted.
- Excluded up front: every page URL in `manifest.yaml` and every Commons SHA-1 from round 1's selection.
- Title/description keyword filter (people, museums, memorials, logos, scans, historic dates), photos dated before 2008 dropped, then a hand-picked shortlist of 166 by title, then by-eye review of every 330 px thumbnail on contact sheets, and a second look at full size for photos with people.

## Rejected at review (examples, with reason)

- Identifiable people or faces: speaker in Prague square, flipchart meeting, man at a blackboard, cafe/bakery staff, woman drinking coffee, festival crowd at mid distance (Taipei North Gate, York mulled-wine stall), surf-rental staff (Waikiki) and a reader in a reading room (both seen at full size), motorbike rider at a fruit stall.
- Possible personal data: a boarding pass in hand (passenger/booking fields), a handwritten restaurant bill with the waiter's name, a hotel voucher with guest fields (Belarus), a home office with a framed diploma.
- Logos or branding as subject: Nike shoe wall, pet-food brand aisle, festival logo sign, storefront with brand signage, printed cartoon artwork.
- Low quality: a climbing-wall photo that was only 737x1600 px / 159 KB once downloaded.
- Weak or off-category: event-hall climbing wall, sports hall exterior, a door, plus many good near-alternatives trimmed for balance (a second ramen, a second field, hotel rooms already in travel, etc.).

## Processing

- Download client: User-Agent `SandroidResearchBot/0.2 (research; no contact)`, no personal data. API calls ~1 per 2 s plus response time; HTTP 429s on the API (Retry-After 12-16 s) were waited out exactly. Review thumbnails (330 px) and originals from upload.wikimedia.org at 1 request per 20 s. Thumbnails (166) caused no 429s. Originals got HTTP 429 with `Retry-After: 600` roughly every 10 files; each was waited out exactly (7 times), never a hard block.
- Originals verified against the Commons SHA-1, JPEG SOI marker, Pillow `verify()`. `original_had_exif` / `original_had_gps` from the original's EXIF.
- Dedup: sha256 and pHash (imagehash, distance <= 6) against every file in `photos/files/` at finalisation time (round 1 `wm-0001..0140`, `ss-*`, and the parallel `openverse` agent's `ov-0001..ov-0083`), and within this set. No duplicates found; the closest pHash distance of any new file to any other pack file is 16.
- Size budget 250 MB: the largest originals with long side > 3000 px were downscaled in a copy to 3000 px long side (Pillow LANCZOS, q90, original EXIF and ICC kept); `*_original` fields describe the Commons original. No Commons thumbnail URL was used as a stored file.
- `has_people: true` = people visible but not identifiable (distant, from behind, silhouettes, or only hands/feet). Category `selfie_like_no_face` is hands and feet only.
- Privacy note: as in round 1, many originals carry GPS/camera EXIF; Sandroid must rewrite or strip EXIF before seeding.

## Counts

| category | n |
|---|---|
| document_like | 10 |
| event | 5 |
| food | 8 |
| interior | 7 |
| landmark_generic | 8 |
| pet | 8 |
| selfie_like_no_face | 5 |
| shopping | 4 |
| sport | 10 |
| travel | 6 |

Total: 71 photos, 215.8 MB stored; 4 downscaled; country-neutral 49/71; originals with GPS EXIF 24/71.

## Per-file attribution (CC0 needs none; recorded anyway)

| id | Commons file | author | licence |
|---|---|---|---|
| wm-0141 | [StadiumSeats.jpg](https://commons.wikimedia.org/wiki/File:StadiumSeats.jpg) | Raysonho @ Open Grid Scheduler / Grid Engine | CC0-1.0 |
| wm-0142 | [Adidas soccer ball on a grass pitch (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Adidas_soccer_ball_on_a_grass_pitch_(Unsplash).jpg) | Peter Glaser baraida | CC0-1.0 |
| wm-0143 | [20120316-fußballplatz-sportzentrum-sportanlage-sandriesel-fc-hörbranz-1.jpg](https://commons.wikimedia.org/wiki/File:20120316-fu%C3%9Fballplatz-sportzentrum-sportanlage-sandriesel-fc-h%C3%B6rbranz-1.jpg) | BikeMike | CC0-1.0 |
| wm-0144 | [Table Tennis Racket.jpg](https://commons.wikimedia.org/wiki/File:Table_Tennis_Racket.jpg) | Erlkönig1732 | CC0-1.0 |
| wm-0145 | [Bowling Alley Pelixir Oulu 20150110.JPG](https://commons.wikimedia.org/wiki/File:Bowling_Alley_Pelixir_Oulu_20150110.JPG) | Estormiz | CC0-1.0 |
| wm-0146 | [Ski school on moguls, Edelweiss slope, Les Arcs.jpg](https://commons.wikimedia.org/wiki/File:Ski_school_on_moguls,_Edelweiss_slope,_Les_Arcs.jpg) | DimiTalen | CC0-1.0 |
| wm-0147 | [Mamaroneck golf club (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Mamaroneck_golf_club_(Unsplash).jpg) | juan gomez jgomez20 | CC0-1.0 |
| wm-0148 | [Small soccer goal on a foggy field (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Small_soccer_goal_on_a_foggy_field_(Unsplash).jpg) | Glen Carrie glencarrie | CC0-1.0 |
| wm-0149 | [Outdoor ping pong table.jpg](https://commons.wikimedia.org/wiki/File:Outdoor_ping_pong_table.jpg) | Bezprezdivky | CC0-1.0 |
| wm-0150 | [White kayak on a river (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:White_kayak_on_a_river_(Unsplash).jpg) | Laura Lefurgey-Smith lauralefurgeysmith | CC0-1.0 |
| wm-0151 | [Epsom Clock Tower (August 2021).jpg](https://commons.wikimedia.org/wiki/File:Epsom_Clock_Tower_(August_2021).jpg) | Mertbiol | CC0-1.0 |
| wm-0152 | [Windmill on Levkas beach, pic1.JPG](https://commons.wikimedia.org/wiki/File:Windmill_on_Levkas_beach,_pic1.JPG) | Alf van Beem | CC0-1.0 |
| wm-0153 | [Old town gate of Colonia.JPG](https://commons.wikimedia.org/wiki/File:Old_town_gate_of_Colonia.JPG) | Ypsilon from Finland | CC0-1.0 |
| wm-0154 | [Lake beach pier (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Lake_beach_pier_(Unsplash).jpg) | JD Weiher jdweiher | CC0-1.0 |
| wm-0155 | [Facade Roskilde cathedral Denmark.jpg](https://commons.wikimedia.org/wiki/File:Facade_Roskilde_cathedral_Denmark.jpg) | Jebulon | CC0-1.0 |
| wm-0156 | [Aqueduct Segovia 2 2012.jpg](https://commons.wikimedia.org/wiki/File:Aqueduct_Segovia_2_2012.jpg) | Jebulon | CC0-1.0 |
| wm-0157 | [Boats in Reykjavik's Old Harbour.JPG](https://commons.wikimedia.org/wiki/File:Boats_in_Reykjavik%27s_Old_Harbour.JPG) | Ypsilon from Finland | CC0-1.0 |
| wm-0158 | [Albany Covered Bridge.jpg](https://commons.wikimedia.org/wiki/File:Albany_Covered_Bridge.jpg) | Waz8 | CC0-1.0 |
| wm-0159 | [Shop window with prices list at a stationary shop near 加計塚小学校.jpg](https://commons.wikimedia.org/wiki/File:Shop_window_with_prices_list_at_a_stationary_shop_near_%E5%8A%A0%E8%A8%88%E5%A1%9A%E5%B0%8F%E5%AD%A6%E6%A0%A1.jpg) | Syced | CC0-1.0 |
| wm-0160 | [Envelopes (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Envelopes_(Unsplash).jpg) | Joanna Kosinska joannakosinska | CC0-1.0 |
| wm-0161 | [Think Outside Of The Box.jpg](https://commons.wikimedia.org/wiki/File:Think_Outside_Of_The_Box.jpg) | Karolina Grabowska | CC0-1.0 |
| wm-0162 | [Baijiu price list in Haikou 2018 09 11.jpg](https://commons.wikimedia.org/wiki/File:Baijiu_price_list_in_Haikou_2018_09_11.jpg) | Anna Frodesiak | CC0-1.0 |
| wm-0163 | [The Sussex Peasant price list 2023-10-22.jpg](https://commons.wikimedia.org/wiki/File:The_Sussex_Peasant_price_list_2023-10-22.jpg) | Andy Li | CC0-1.0 |
| wm-0164 | [Train timetable of Maputo.jpg](https://commons.wikimedia.org/wiki/File:Train_timetable_of_Maputo.jpg) | Carmelobrianza | CC0-1.0 |
| wm-0165 | [Moscow Oblast Bus Ticket 2014.jpg](https://commons.wikimedia.org/wiki/File:Moscow_Oblast_Bus_Ticket_2014.jpg) | Spacekid | CC0-1.0 |
| wm-0166 | [Train ticket - from Brighton to Portsmouth & S or Harbour.jpg](https://commons.wikimedia.org/wiki/File:Train_ticket_-_from_Brighton_to_Portsmouth_%26_S_or_Harbour.jpg) | Andy Li | CC0-1.0 |
| wm-0167 | [Ticket du train touristique du Cotentin.jpg](https://commons.wikimedia.org/wiki/File:Ticket_du_train_touristique_du_Cotentin.jpg) | Rc1959 | CC0-1.0 |
| wm-0168 | [Receipt zajazd Szałas Żory.jpg](https://commons.wikimedia.org/wiki/File:Receipt_zajazd_Sza%C5%82as_%C5%BBory.jpg) | Abraham | CC0-1.0 |
| wm-0169 | [Plaza Hotel room, Sept 2017.jpg](https://commons.wikimedia.org/wiki/File:Plaza_Hotel_room,_Sept_2017.jpg) | Thomson200 | CC0-1.0 |
| wm-0170 | [White towel in tiled bathroom (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:White_towel_in_tiled_bathroom_(Unsplash).jpg) | David Cohen dcp | CC0-1.0 |
| wm-0171 | [Home office (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Home_office_(Unsplash).jpg) | Michał Kubalczyk rev3n | CC0-1.0 |
| wm-0172 | [Chevening Flats staircase window.jpg](https://commons.wikimedia.org/wiki/File:Chevening_Flats_staircase_window.jpg) | Siobhan Leachman | CC0-1.0 |
| wm-0173 | [Apartment hotel Nice.jpg](https://commons.wikimedia.org/wiki/File:Apartment_hotel_Nice.jpg) | Paikan06 | CC0-1.0 |
| wm-0174 | [Jumpru Pub Bar Oulu 20130718.jpg](https://commons.wikimedia.org/wiki/File:Jumpru_Pub_Bar_Oulu_20130718.jpg) | Estormiz | CC0-1.0 |
| wm-0175 | [Villa Fallet View to Bathroom.jpg](https://commons.wikimedia.org/wiki/File:Villa_Fallet_View_to_Bathroom.jpg) | Zwantzig | CC0-1.0 |
| wm-0176 | [GreyoundPose.jpg](https://commons.wikimedia.org/wiki/File:GreyoundPose.jpg) | L. Bower | CC0-1.0 |
| wm-0177 | [2011.09.17.113926 Cats window Place de lÉtolie Obernai.jpg](https://commons.wikimedia.org/wiki/File:2011.09.17.113926_Cats_window_Place_de_l%C3%89tolie_Obernai.jpg) | Hermann Luyken | CC0-1.0 |
| wm-0178 | [Rabbit (red eye).JPG](https://commons.wikimedia.org/wiki/File:Rabbit_(red_eye).JPG) | آرمین | CC0-1.0 |
| wm-0179 | [Pet Hamster eating cucumber.JPG](https://commons.wikimedia.org/wiki/File:Pet_Hamster_eating_cucumber.JPG) | Bernard Ladenthin | CC0-1.0 |
| wm-0180 | [Orange fish in an aquarium (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Orange_fish_in_an_aquarium_(Unsplash).jpg) | Frederica Diamanta frederica | CC0-1.0 |
| wm-0181 | [Melopsittacus-undulatus-1.jpg](https://commons.wikimedia.org/wiki/File:Melopsittacus-undulatus-1.jpg) | MartinThoma | CC0-1.0 |
| wm-0182 | [Sleeping Border Terrier.JPG](https://commons.wikimedia.org/wiki/File:Sleeping_Border_Terrier.JPG) | Alanthebox | CC0-1.0 |
| wm-0183 | [A Guinea pig and its carrot.jpg](https://commons.wikimedia.org/wiki/File:A_Guinea_pig_and_its_carrot.jpg) | Kuli | CC0-1.0 |
| wm-0184 | [Breakfast at Philippe's.jpg](https://commons.wikimedia.org/wiki/File:Breakfast_at_Philippe%27s.jpg) | Temaciejewski | CC0-1.0 |
| wm-0185 | [Tomato cheese ramen 001.jpg](https://commons.wikimedia.org/wiki/File:Tomato_cheese_ramen_001.jpg) | Ocdp | CC0-1.0 |
| wm-0186 | [Dumplings (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Dumplings_(Unsplash).jpg) | Charles Deluvio charlesdeluvio | CC0-1.0 |
| wm-0187 | [Shrimp tacos.jpg](https://commons.wikimedia.org/wiki/File:Shrimp_tacos.jpg) | Alan Levine | CC0-1.0 |
| wm-0188 | [Croissants au beurre (18953292873).jpg](https://commons.wikimedia.org/wiki/File:Croissants_au_beurre_(18953292873).jpg) | Herry Wibisono (herryway) | CC0-1.0 |
| wm-0189 | [Pancakes with Berries (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Pancakes_with_Berries_(Unsplash).jpg) | Herson Rodriguez hero | CC0-1.0 |
| wm-0190 | [ミックスサンド.jpg](https://commons.wikimedia.org/wiki/File:%E3%83%9F%E3%83%83%E3%82%AF%E3%82%B9%E3%82%B5%E3%83%B3%E3%83%89.jpg) | Nils R. Barth | CC0-1.0 |
| wm-0191 | [Grilling Sausages (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Grilling_Sausages_(Unsplash).jpg) | The Digital Marketing Collaboration thedmcsa | CC0-1.0 |
| wm-0192 | [Tea cup (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Tea_cup_(Unsplash).jpg) | Sylwia Bartyzel sylwiabartyzel | CC0-1.0 |
| wm-0193 | [Rochester, United States (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Rochester,_United_States_(Unsplash).jpg) | Kyle Ryan kylry | CC0-1.0 |
| wm-0194 | [Hot coffee on a cold day (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Hot_coffee_on_a_cold_day_(Unsplash).jpg) | PICSELI picseli | CC0-1.0 |
| wm-0195 | [Fresh strawberries (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Fresh_strawberries_(Unsplash).jpg) | Artur Rutkowski alienowicz | CC0-1.0 |
| wm-0196 | [Walking in a Utah winter (Unsplash).jpg](https://commons.wikimedia.org/wiki/File:Walking_in_a_Utah_winter_(Unsplash).jpg) | Greg Rakozy grakozy | CC0-1.0 |
| wm-0197 | [Fireworks-2014-07-04-pittsburgh-01.jpg](https://commons.wikimedia.org/wiki/File:Fireworks-2014-07-04-pittsburgh-01.jpg) | MartinThoma | CC0-1.0 |
| wm-0198 | [Calgary Folk Music Festival 2023 audience viewing main stage concert.jpg](https://commons.wikimedia.org/wiki/File:Calgary_Folk_Music_Festival_2023_audience_viewing_main_stage_concert.jpg) | JollyJamboree | CC0-1.0 |
| wm-0199 | [Marx-Engels-Forum with christmas market at night 2021-11-25 01.jpg](https://commons.wikimedia.org/wiki/File:Marx-Engels-Forum_with_christmas_market_at_night_2021-11-25_01.jpg) | Leonhard Lenz | CC0-1.0 |
| wm-0200 | [Celebration Chinese Lantern Festival.jpg](https://commons.wikimedia.org/wiki/File:Celebration_Chinese_Lantern_Festival.jpg) | tookapic | CC0-1.0 |
| wm-0201 | [2023 Futagotamagawa fireworks 2.jpg](https://commons.wikimedia.org/wiki/File:2023_Futagotamagawa_fireworks_2.jpg) | Syced | CC0-1.0 |
| wm-0202 | [TJ Produce.jpg](https://commons.wikimedia.org/wiki/File:TJ_Produce.jpg) | Francinegirvan | CC0-1.0 |
| wm-0203 | [Detergents-department-ramat-gan-supermarket-october-2015.jpg](https://commons.wikimedia.org/wiki/File:Detergents-department-ramat-gan-supermarket-october-2015.jpg) | Rakoon | CC0-1.0 |
| wm-0204 | [Pasty stall in the Pannier Market, Plymouth, Devon - November 2023.jpg](https://commons.wikimedia.org/wiki/File:Pasty_stall_in_the_Pannier_Market,_Plymouth,_Devon_-_November_2023.jpg) | Mutney | CC0-1.0 |
| wm-0205 | [Vitrine de patisserie chinoise avenue de Choisy.JPG](https://commons.wikimedia.org/wiki/File:Vitrine_de_patisserie_chinoise_avenue_de_Choisy.JPG) | Dinkum | CC0-1.0 |
| wm-0206 | [SZ 深圳 Shenzhen 寶安 BaoAn train window June 2024 R12S 160.jpg](https://commons.wikimedia.org/wiki/File:SZ_%E6%B7%B1%E5%9C%B3_Shenzhen_%E5%AF%B6%E5%AE%89_BaoAn_train_window_June_2024_R12S_160.jpg) | NGAON32 Hongam | CC0-1.0 |
| wm-0207 | [Ötztal Alps airplane window 2017.jpg](https://commons.wikimedia.org/wiki/File:%C3%96tztal_Alps_airplane_window_2017.jpg) | Syd Storm | CC0-1.0 |
| wm-0208 | [2015.06.16.164942 Bed room 118 Judges Country House Hotel Kirklevington.jpg](https://commons.wikimedia.org/wiki/File:2015.06.16.164942_Bed_room_118_Judges_Country_House_Hotel_Kirklevington.jpg) | Hermann Luyken | CC0-1.0 |
| wm-0209 | [Departure Board at ORD.jpg](https://commons.wikimedia.org/wiki/File:Departure_Board_at_ORD.jpg) | Redolta | CC0-1.0 |
| wm-0210 | [DSB IC3 interior.JPG](https://commons.wikimedia.org/wiki/File:DSB_IC3_interior.JPG) | My another account (talk) | CC0-1.0 |
| wm-0211 | [CDG airport terminal 2 at dusk.jpg](https://commons.wikimedia.org/wiki/File:CDG_airport_terminal_2_at_dusk.jpg) | Syced | CC0-1.0 |
