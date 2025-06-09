import psycopg2

try:
    connection = psycopg2.connect(
        dbname="crop_insurance_sql",
        user="crop_insurance_sql_user",
        password="5EHUihWGBQ9771bziRAbgLuUF6zmRSZ1",
        host="dpg-d12k28buibrs73fa0vn0-a.oregon-postgres.render.com",
        port="5432"
    )

    cursor = connection.cursor()

    with open("converted_crop_insurance_postgres.sql", "r") as file:
        sql = file.read()
        cursor.execute(sql)

    connection.commit()
    cursor.close()
    connection.close()

    print("✅ SQL file executed and database is ready!")

except Exception as e:
    print("❌ Error occurred:", e)
